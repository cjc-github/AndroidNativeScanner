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

On top of that, :func:`propagate_taint` answers a narrower question: does a
value that came in as an ABI argument reach a given register? The sources are
the calling convention's argument registers, so a tainted register means
"this value is derived from what the caller passed in". The pass is
intra-procedural and may-analysis: it never claims a value *cannot* be
attacker-controlled, only where it *is* derived from an argument.
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


#: Where a function's return value lands, per architecture family.
_RETURN_REGISTER = {
    "x86": "rax",
    "x86-64": "rax",
    "aarch64": "x0",
    "arm": "r0",
}

#: The registers the calling convention passes arguments in. They are the
#: taint sources of an intra-procedural analysis.
#: The decoder reports the family as ``x86`` for both bit widths, so the
#: argument registers are chosen by the profile's width.
_ARGUMENT_SOURCES = {
    "x86-64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    # The 32-bit SysV convention passes the first four arguments on the
    # stack; ``eax``/``edx``/``ecx``/``esi`` are only the varargs
    # registers, so they are not sources of a general argument.
    "x86": (),
    "aarch64": tuple(f"x{index}" for index in range(8)),
}

#: Registers that hold the stack pointer or the frame pointer. They are never
#: caller-supplied values, so a taint that starts there would be meaningless.
_NON_ARGUMENT_REGISTERS = frozenset({"rsp", "rbp", "esp", "ebp", "sp"})

#: Registers a call may clobber. The taint of these is dropped at a call,
#: because the callee may write them.
_CALLER_SAVED = {
    "x86-64": ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
    "x86": ("eax", "ecx", "edx", "esi", "edi", "ebp", "esp"),
    "aarch64": tuple(f"x{index}" for index in range(18)),
}

_CALL_MNEMONICS = frozenset({"call", "bl", "blr"})


@dataclass(frozen=True)
class TaintRecord:
    """One taint fact: a register that holds a tainted value."""

    source: str
    """Where the value came from: an argument register, or a source function."""
    target: str
    """The register that received the tainted value."""
    address: int
    """Where the tainted value was produced (or consumed at a call)."""
    depth: int
    """How many definitions away the value is from the source."""
    kind: str
    """``copy`` for a register-to-register move, ``call-argument`` when a
    tainted value is handed to a call, ``source-return`` when a source
    function's return value enters the flow, ``source-argument`` when a
    source function's argument is the tainted one."""
    origin: str = ""
    """The source function the value came from, when there is one."""


@dataclass(frozen=True)
class TaintFlow:
    """The taint facts of one function."""

    records: tuple[TaintRecord, ...] = ()
    tainted_registers: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    """The source functions whose data entered this function."""

    @property
    def count(self) -> int:
        return len(self.records)


def argument_sources(arch: str, *, is64: bool = True) -> tuple[str, ...]:
    """The argument registers of ``arch``, normalized to their parent.

    ``arch`` is the decoder's family name, which is ``x86`` for both bit
    widths, so ``is64`` decides whether the SysV x86-64 registers apply.
    """
    if arch == "x86":
        arch = "x86-64" if is64 else "x86"
    table = _ARGUMENT_SOURCES.get(arch)
    if table is None:
        return ()
    resolved: list[str] = []
    for name in table:
        parent = normalise_register(name, "x86" if arch in ("x86", "x86-64") else arch)
        if parent is None or parent in _NON_ARGUMENT_REGISTERS:
            continue
        if parent not in resolved:
            resolved.append(parent)
    return tuple(resolved)


def _is_memory_destination(operands: str) -> bool:
    """Whether the instruction writes through a memory operand.

    The shared operand heuristic treats the first register in the operand
    text as the destination. For ``mov [rdi], rax`` that register is a base
    pointer, not a destination, so the taint pass must not kill it.
    """
    first = operands.split(",")[0] if operands else ""
    return "[" in first


def propagate_taint(
    instructions,
    graph: ControlFlowGraph,
    arch: str,
    *,
    sources: tuple[str, ...] | None = None,
    max_depth: int = 64,
    is64: bool = True,
    source_targets: dict | None = None,
) -> TaintFlow:
    """Propagate taint from the ABI argument registers through a function.

    ``instructions`` yields ``(address, size, mnemonic, operands)`` records and
    ``graph`` is that function's CFG, so the propagation follows the real
    control flow instead of the address order.

    A register is tainted when it holds a value derived from an argument
    register. Writing a register kills its taint unless the written value
    itself reads a tainted register, and a call kills the taint of the
    registers it may clobber -- while the taint *into* the call is recorded,
    because a tainted argument reaching a call is the fact that matters.

    ``source_targets`` maps a call target address to a source function from
    the taint library. Calling such a function makes its return value (or
    the buffer of its argument) tainted, which is how data that originates
    outside the program enters the flow.
    """
    if not graph.blocks:
        return TaintFlow()

    source_registers = (
        tuple(sources) if sources is not None else argument_sources(arch, is64=is64)
    )
    if not source_registers:
        return TaintFlow()

    grouped = _group_by_block(
        sorted(instructions, key=lambda item: item[0]), graph.blocks
    )
    callersaved = {
        normalise_register(name, "x86" if arch in ("x86", "x86-64") else arch)
        for name in _CALLER_SAVED.get(arch, ())
    }
    callersaved.discard(None)

    # ``state`` maps a register to (source register, depth, definition address).
    incoming: dict[int, dict[str, tuple[str, int, int]]] = {
        block.start: {} for block in graph.blocks
    }
    outgoing: dict[int, dict[str, tuple[str, int, int]]] = {
        block.start: {} for block in graph.blocks
    }
    if graph.entry is not None and graph.entry in incoming:
        incoming[graph.entry] = {
            name: (name, 0, 0) for name in source_registers if name
        }

    targets = dict(source_targets or {})

    records: list[TaintRecord] = []
    seen_records: set[tuple] = set()

    for _round in range(len(graph.blocks) + 1):
        changed = False
        for block in graph.blocks:
            state = dict(incoming[block.start])
            produced, flows = _transfer(
                grouped.get(block.start, ()),
                state,
                arch,
                callersaved,
                source_registers,
                max_depth,
                targets,
                is64,
            )
            for flow in flows:
                key = (flow.source, flow.target, flow.address, flow.kind)
                if key not in seen_records:
                    seen_records.add(key)
                    records.append(flow)
            if produced != outgoing[block.start]:
                outgoing[block.start] = produced
                changed = True
            for successor in block.successors:
                if successor not in incoming:
                    # A successor outside the recovered graph (a call target
                    # that is not a block of this function) carries no state.
                    continue
                merged = _merge(incoming[successor], produced)
                if merged != incoming[successor]:
                    incoming[successor] = merged
                    changed = True
        if not changed:
            break

    tainted = tuple(
        sorted(
            {
                name
                for state in outgoing.values()
                for name in state
            }
        )
    )
    return TaintFlow(records=tuple(records), tainted_registers=tainted)


def _merge(
    incoming: dict[str, tuple[str, int, int]],
    produced: dict[str, tuple[str, int, int]],
) -> dict[str, tuple[str, int, int]]:
    """Merge a predecessor's state into a block's incoming state."""
    merged = dict(incoming)
    for name, value in produced.items():
        current = merged.get(name)
        if current is None or value[1] < current[1]:
            merged[name] = value
    return merged


def _transfer(
    records,
    state: dict[str, tuple[str, int, int]],
    arch: str,
    callersaved: set,
    argument_registers: tuple[str, ...],
    max_depth: int,
    source_targets: dict | None = None,
    is64: bool = True,
) -> tuple[dict[str, tuple[str, int, int]], list[TaintRecord]]:
    """Run one block's instructions and return the state and the taint facts."""
    flows: list[TaintRecord] = []
    targets = source_targets or {}
    for address, _size, mnemonic, operands in records:
        reads, writes = instruction_locations(mnemonic, operands, arch)

        if mnemonic in _CALL_MNEMONICS:
            # A call hands over whatever sits in the argument registers of the
            # calling convention, so that is where the taint is consumed --
            # not in the operand text, which names the callee, not the
            # arguments. A tainted value handed over is exactly the fact the
            # security analyzers look for.
            for name in argument_registers:
                value = state.get(name)
                if value is not None:
                    flows.append(
                        TaintRecord(
                            source=value[0],
                            target=name,
                            address=address,
                            depth=value[1],
                            kind="call-argument",
                        )
                    )
            # The callee may write the caller-saved registers, so their taint
            # is dropped here -- before the source call contributes, because
            # a source's return value lands in one of them.
            for name in callersaved:
                state.pop(name, None)
            _apply_source_call(
                address, operands, arch, state, flows, targets, argument_registers
            )
            continue

        if _is_memory_destination(operands):
            # A store through a pointer: the pointer is read, not written.
            continue

        for name in sorted(writes):
            value = None
            for read in sorted(reads):
                candidate = state.get(read)
                if candidate is not None and candidate[1] < max_depth:
                    value = candidate
                    break
            if value is None:
                state.pop(name, None)
                continue
            state[name] = (value[0], value[1] + 1, address)
            flows.append(
                TaintRecord(
                    source=value[0],
                    target=name,
                    address=address,
                    depth=value[1] + 1,
                    kind="copy",
                )
            )
    return state, flows


def _apply_source_call(
    address: int,
    operands: str,
    arch: str,
    state: dict[str, tuple[str, int, int]],
    flows: list[TaintRecord],
    source_targets: dict,
    argument_registers: tuple[str, ...],
) -> None:
    """Let a source function contribute taint to the caller's registers.

    A source with kind ``return`` taints the return register, because the
    value it produces lands there. A source with kind ``argument`` taints
    the register that carried the buffer the source wrote into.
    """
    if not source_targets:
        return
    target = _direct_call_target(operands)
    if target is None:
        return
    source = source_targets.get(target)
    if source is None:
        return

    kind = str(source.get("kind") or "return")
    symbol = str(source.get("symbol") or "")
    if kind == "argument":
        index = int(source.get("argument") or 0)
        if index >= len(argument_registers):
            return
        register = argument_registers[index]
        flows.append(
            TaintRecord(
                source=symbol or str(source.get("name") or ""),
                target=register,
                address=address,
                depth=0,
                kind="source-argument",
                origin=symbol,
            )
        )
        state[register] = (symbol or str(source.get("name") or ""), 0, address)
        return

    family = "x86-64" if arch in ("x86", "x86-64") else arch
    register = _RETURN_REGISTER.get(family)
    if register is None:
        return
    flows.append(
        TaintRecord(
            source=symbol or str(source.get("name") or ""),
            target=register,
            address=address,
            depth=0,
            kind="source-return",
            origin=symbol,
        )
    )
    state[register] = (symbol or str(source.get("name") or ""), 0, address)


def _direct_call_target(operands: str) -> int | None:
    """The address a direct call jumps to, or ``None``."""
    for part in reversed(operands.split(",")):
        candidate = part.strip().lstrip("#").strip()
        if not candidate:
            continue
        if candidate.startswith("0x") or candidate.isdigit():
            try:
                return int(candidate, 0)
            except ValueError:
                return None
    return None
