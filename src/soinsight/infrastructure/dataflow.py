"""Use-def and reaching-definition analysis over a function's CFG.

Register liveness is derived from the instruction operands themselves rather
than from a decoder's register summary: the operand text names the registers
it reads and writes, which is enough for the facts this capability reports
and never contradicts them. Sub-registers fold into the architectural
register so ``eax`` and ``rax`` are the same location.

Intra-procedural analysis comes first: each basic block gets the defs and
uses it contains, and a forward data-flow pass propagates reaching
definitions across block boundaries. Inter-procedural propagation is out of
scope; the facts never claim it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .cfg import ControlFlowGraph

# x86-64 register names. A sub-register maps onto its 64-bit parent because a
# use-def chain cares about the location, not the access width.
_X86_PARENTS = {}
for _index, _name in enumerate(("rax", "rbx", "rcx", "rdx")):
    _X86_PARENTS[_name] = _name
    _X86_PARENTS[f"e{_name[1:]}"] = _name
    _X86_PARENTS[f"{_name[0]}x"] = _name
    _X86_PARENTS[f"{_name[0]}l"] = _name
_X86_PARENTS.update(
    {
        "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
)
for _index in range(8, 16):
    _base = f"r{_index}"
    _X86_PARENTS[_base] = _base
    _X86_PARENTS[f"r{_index}d"] = _base
    _X86_PARENTS[f"r{_index}w"] = _base
    _X86_PARENTS[f"r{_index}b"] = _base

# AArch64 register names. w<n> folds into x<n>; v<n> is a separate location.
_AARCH64_PARENTS = {f"x{index}": f"x{index}" for index in range(31)}
_AARCH64_PARENTS["sp"] = "sp"
_AARCH64_PARENTS.update({f"w{index}": f"x{index}" for index in range(31)})
_AARCH64_PARENTS.update({f"v{index}": f"v{index}" for index in range(32)})

# Mnemonics whose operands are all reads: they never define a location.
_READ_ONLY = frozenset(
    {"cmp", "test", "push", "cbz", "cbnz", "tbz", "tbnz", "ret", "b", "jmp"}
)
# Operand tokens that are syntax, not registers.
_SYNTAX = frozenset({",", "+", "-", "*", "[", "]", "#", "ptr", ":"})


@dataclass(frozen=True)
class Definition:
    """One definition of a location at an instruction."""

    location: str
    address: int
    block: int


@dataclass(frozen=True)
class Use:
    """One use of a location, with the definitions that reach it."""

    location: str
    address: int
    block: int
    reaching: tuple[Definition, ...] = ()


@dataclass(frozen=True)
class BlockFlow:
    """Use-def facts for one basic block."""

    start: int
    defs: tuple[Definition, ...]
    uses: tuple[Use, ...]


@dataclass(frozen=True)
class DataFlow:
    """Per-block use-def plus reaching definitions for one function."""

    blocks: tuple[BlockFlow, ...]
    reaching_pairs: int

    @property
    def def_count(self) -> int:
        return sum(len(block.defs) for block in self.blocks)

    @property
    def use_count(self) -> int:
        return sum(len(block.uses) for block in self.blocks)


def normalise_register(token: str, arch: str) -> str | None:
    """Map an operand token to the architectural register it names.

    Returns ``None`` when the token is not a register of ``arch``, so callers
    ignore immediates, memory displacements and symbol names.
    """
    name = token.strip().lstrip("%").lower()
    if not name:
        return None
    table = _AARCH64_PARENTS if arch == "aarch64" else _X86_PARENTS
    return table.get(name)


def _tokens(operands: str) -> list[str]:
    """Split an operand string into tokens, keeping bracket contents intact."""
    text = operands
    for character in "[]<>,-+*#:":
        text = text.replace(character, f" {character} ")
    return [token for token in text.split() if token]


def instruction_locations(
    mnemonic: str, operands: str, arch: str
) -> tuple[set[str], set[str]]:
    """Return ``(reads, writes)`` for one instruction.

    The destination is the first operand for the majority of two-operand
    instructions. Memory operands contribute their base register, not an
    effective-address location, so a load through a pointer reads the pointer.
    """
    registers: list[str] = []
    for token in _tokens(operands):
        if token in _SYNTAX:
            continue
        name = normalise_register(token, arch)
        if name is not None and name not in registers:
            registers.append(name)
    if not registers:
        return set(), set()
    if mnemonic in _READ_ONLY:
        return set(registers), set()

    destination = _first_register(operands, arch)
    if destination is None:
        return set(registers), set()
    return {name for name in registers if name != destination}, {destination}


def _first_register(operand: str, arch: str) -> str | None:
    """First register named by ``operand``, or ``None`` when there is none."""
    for token in _tokens(operand):
        if token in _SYNTAX:
            continue
        name = normalise_register(token, arch)
        if name is not None:
            return name
    return None


def analyse(
    instructions,
    graph: ControlFlowGraph,
    arch: str,
    max_pairs: int = 20000,
) -> DataFlow:
    """Build use-def facts and propagate reaching definitions.

    ``instructions`` yields ``(address, size, mnemonic, operands)`` records for
    one function and ``graph`` is that function's CFG, so block boundaries and
    successors are already known.
    """
    if not instructions or not graph.blocks:
        return DataFlow((), 0)

    ordered = sorted(instructions, key=lambda item: item[0])
    grouped = _group_by_block(ordered, graph.blocks)

    blocks: list[BlockFlow] = []
    local: dict[int, list[tuple[int, str, Definition | None]]] = {}
    for block in graph.blocks:
        definitions: list[Definition] = []
        uses: list[Use] = []
        events: list[tuple[int, str, Definition | None]] = []
        for address, _size, mnemonic, operands in grouped.get(block.start, ()):
            reads, writes = instruction_locations(mnemonic, operands, arch)
            for location in sorted(reads):
                uses.append(Use(location, address, block.start))
                events.append((address, location, None))
            for location in sorted(writes):
                definition = Definition(location, address, block.start)
                definitions.append(definition)
                events.append((address, location, definition))
        blocks.append(BlockFlow(block.start, tuple(definitions), tuple(uses)))
        local[block.start] = sorted(
            events, key=lambda item: (item[0], item[2] is None)
        )

    entry = _entry_definitions(blocks, graph)
    resolved: list[BlockFlow] = []
    pairs = 0
    for block in blocks:
        flowing = dict(entry.get(block.start, {}))
        resolved_uses: list[Use] = []
        for address, location, definition in local[block.start]:
            if definition is not None:
                # A definition kills what flowed in for its location, and the
                # later uses in this block see this definition instead.
                flowing[location] = frozenset({definition})
                continue
            if pairs >= max_pairs:
                resolved_uses.append(Use(location, address, block.start))
                continue
            definitions = tuple(
                sorted(
                    flowing.get(location, frozenset()),
                    key=lambda item: (item.address, item.location),
                )
            )
            resolved_uses.append(Use(location, address, block.start, definitions))
            pairs += len(definitions)
        resolved.append(BlockFlow(block.start, block.defs, tuple(resolved_uses)))
    return DataFlow(tuple(resolved), pairs)


def _group_by_block(ordered, blocks) -> dict[int, tuple]:
    """Assign each instruction to the block whose ``[start, end)`` contains it."""
    ranges = [(block.start, block.end) for block in blocks]
    grouped: dict[int, list] = {}
    for record in ordered:
        for start, end in ranges:
            if start <= record[0] < end:
                grouped.setdefault(start, []).append(record)
                break
    return {start: tuple(records) for start, records in grouped.items()}


def _entry_definitions(
    blocks: list[BlockFlow], graph: ControlFlowGraph
) -> dict[int, dict[str, frozenset[Definition]]]:
    """Definitions reaching the entry of each block.

    ``in`` is recomputed from a block's predecessors every round, so the
    transfer is monotone and the fixed point is reached within one round per
    block on the longest acyclic path. A block's own last definition of a
    location kills what flowed in, which is what the successors observe.
    """
    by_start = {block.start: block for block in blocks}
    predecessors: dict[int, list[int]] = {block.start: [] for block in blocks}
    for block in graph.blocks:
        for successor in block.successors:
            if successor in predecessors:
                predecessors[successor].append(block.start)

    incoming: dict[int, dict[str, frozenset[Definition]]] = {
        block.start: {} for block in blocks
    }
    order = [block.start for block in blocks]
    for _round in range(len(order) + 1):
        changed = False
        for start in order:
            merged: dict[str, frozenset[Definition]] = {}
            for predecessor in predecessors[start]:
                for location, definitions in incoming[predecessor].items():
                    merged[location] = merged.get(location, frozenset()) | definitions
            for location, definition in _block_kills(by_start[start]).items():
                merged[location] = frozenset({definition})
            if merged != incoming[start]:
                incoming[start] = merged
                changed = True
        if not changed:
            break
    return incoming


def _block_kills(block: BlockFlow) -> dict[str, Definition]:
    """Last definition per location inside ``block``.

    A block is one transfer step, so the last definition of a location is the
    one that reaches the successors. Uses inside the block still see every
    definition before them, which the per-use pass in :func:`analyse` handles.
    """
    kills: dict[str, Definition] = {}
    for definition in block.defs:
        kills[definition.location] = definition
    return kills
