"""Control-flow graph construction over decoded instructions.

The layer splits a function's instruction stream into basic blocks and
recovers edges. Only provable edges are reported: direct branch targets are
exact, calls are classified by their target, and indirect targets become
``call_indirect`` / ``jump_indirect`` edges without guessing a destination.
A function that falls off the end keeps its trailing block so the graph stays
connected for callers.

Loops are detected with a depth-first back-edge search, so an irreducible
CFG degrades to "no loop reported" instead of a wrong answer.
"""

from __future__ import annotations

from dataclasses import dataclass

# Mnemonics that terminate a basic block, grouped by how the successor is
# determined because the edge kind follows the terminator.
_UNCONDITIONAL_JUMPS = frozenset({"jmp", "b", "br"})
_CONDITIONAL_JUMPS = frozenset(
    {
        "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
        "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno",
        "jp", "jnp", "jc", "jnc", "jecxz", "jrcxz",
        "loop", "loope", "loopne",
    }
)
_CONDITIONAL_AARCH64 = frozenset(
    {
        "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
        "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
        "cbz", "cbnz", "tbz", "tbnz",
    }
)
_CALLS = frozenset({"call", "bl", "blr"})
_RETURNS = frozenset({"ret", "retn", "retf", "iret", "eret"})

_TERMINATORS = (
    _UNCONDITIONAL_JUMPS
    | _CONDITIONAL_JUMPS
    | _CONDITIONAL_AARCH64
    | _CALLS
    | _RETURNS
)


@dataclass(frozen=True)
class BasicBlock:
    """One straight-line code region: ``[start, end)`` with successors."""

    start: int
    end: int  # exclusive
    successors: tuple[int, ...]
    terminator: str | None  # mnemonic that ends the block, if any
    terminator_operands: str = ""  # operands of that terminator


@dataclass(frozen=True)
class ControlFlowGraph:
    """Basic blocks, edges and loop facts for one function."""

    entry: int | None
    blocks: tuple[BasicBlock, ...]
    edges: tuple[tuple[int, int, str], ...]  # (source, target, kind)
    loops: tuple[tuple[int, ...], ...]  # back-edge cycles as block-start tuples

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


def is_terminator(mnemonic: str) -> bool:
    """True when ``mnemonic`` ends a basic block."""
    return mnemonic in _TERMINATORS


def direct_target(operands: str) -> int | None:
    """Parse a literal branch/call target address from ``operands``.

    x86 puts the target first (``0x1000``); AArch64 puts it last after the
    condition register (``w0, #0x1000``). A register or memory operand yields
    ``None`` so indirect targets stay unresolved.
    """
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


def classify_edge(mnemonic: str, operands: str) -> str:
    """Return the edge kind produced by a terminating instruction.

    Kinds: ``branch`` (unconditional jump), ``cond`` (conditional jump),
    ``call`` (direct call), ``call_indirect`` and ``jump_indirect``.
    """
    if mnemonic in _CALLS:
        return "call" if direct_target(operands) is not None else "call_indirect"
    if mnemonic in _UNCONDITIONAL_JUMPS:
        return "branch" if direct_target(operands) is not None else "jump_indirect"
    if mnemonic in _CONDITIONAL_JUMPS or mnemonic in _CONDITIONAL_AARCH64:
        return "cond"
    return "return"


def build_cfg(instructions) -> ControlFlowGraph:
    """Build a CFG from ``(address, size, mnemonic, operands)`` records.

    ``instructions`` may be any iterable; it is materialised once so callers can
    pass a generator. The records must belong to one function. An empty stream
    yields an empty graph rather than a failure.
    """
    records = list(instructions)
    if not records:
        return ControlFlowGraph(None, (), (), ())

    ordered = sorted(records, key=lambda item: item[0])
    leaders = _leaders(ordered)

    blocks: list[BasicBlock] = []
    for index, start in enumerate(leaders):
        end = (
            leaders[index + 1]
            if index + 1 < len(leaders)
            else ordered[-1][0] + ordered[-1][1]
        )
        members = [item for item in ordered if start <= item[0] < end]
        if not members:
            continue
        terminator, operands = _block_terminator(members)
        blocks.append(
            BasicBlock(
                start=start,
                end=end,
                successors=_successors(
                    members, terminator, operands, index, leaders
                ),
                terminator=terminator,
                terminator_operands=operands,
            )
        )

    edges = _edges(blocks)
    loops = _find_loops(blocks, edges)
    return ControlFlowGraph(
        entry=ordered[0][0], blocks=tuple(blocks), edges=tuple(edges), loops=loops
    )


def _leaders(ordered) -> list[int]:
    """Addresses that start a basic block: entry, jump targets and fall-through."""
    starts = {ordered[0][0]}
    for position, item in enumerate(ordered):
        address, size, mnemonic, operands = item
        if not is_terminator(mnemonic):
            continue
        target = direct_target(operands)
        if target is not None:
            starts.add(target)
        # The instruction after a terminator starts a new block.
        if position + 1 < len(ordered):
            starts.add(ordered[position + 1][0])
    return sorted(start for start in starts if start >= ordered[0][0])


def _block_terminator(members) -> tuple[str | None, str]:
    """The block's last instruction when it terminates the block, else ``None``."""
    last = members[-1]
    mnemonic = last[2]
    if is_terminator(mnemonic):
        return mnemonic, last[3]
    return None, ""


def _successors(members, terminator, operands, index, leaders) -> tuple[int, ...]:
    """Successor block starts for one block, without guessing indirect targets."""
    fallthrough = (leaders[index + 1],) if index + 1 < len(leaders) else ()
    if terminator is None:
        return fallthrough
    kind = classify_edge(terminator, operands)
    if kind in ("call", "call_indirect"):
        # A call returns to the fall-through block; the callee is an edge
        # target, not a block successor.
        return fallthrough
    if kind == "return":
        return ()
    target = direct_target(operands)
    if target is None:
        # Indirect branch: the destination is unknown, so no successor edge.
        return ()
    if kind == "cond":
        return tuple(sorted({target, *fallthrough}))
    return (target,)


def _edges(blocks) -> list[tuple[int, int, str]]:
    """Flatten block successors into ``(source, target, kind)`` triples."""
    starts = {block.start for block in blocks}
    edges: list[tuple[int, int, str]] = []
    for block in blocks:
        if block.terminator is None:
            kind = "fallthrough"
        else:
            kind = classify_edge(block.terminator, block.terminator_operands)
        for successor in block.successors:
            if successor in starts:
                edges.append((block.start, successor, kind))
    return edges


def _find_loops(blocks, edges) -> tuple[tuple[int, ...], ...]:
    """Report back-edge cycles as tuples of block starts.

    A depth-first search records the stack; an edge back into the stack marks
    a loop covering that cycle. Only cycles are reported, never a guess at
    iteration counts.
    """
    adjacency: dict[int, list[int]] = {}
    for source, target, _ in edges:
        adjacency.setdefault(source, []).append(target)

    loops: list[tuple[int, ...]] = []
    seen: set[tuple[int, ...]] = set()
    on_stack: list[int] = []
    position: dict[int, int] = {}
    visited: set[int] = set()

    def visit(node: int) -> None:
        position[node] = len(on_stack)
        on_stack.append(node)
        for successor in sorted(adjacency.get(node, ())):
            if successor in position:
                cycle = tuple(on_stack[position[successor] :])
                if cycle and cycle not in seen:
                    seen.add(cycle)
                    loops.append(cycle)
            elif successor not in visited:
                visit(successor)
        on_stack.pop()
        del position[node]
        visited.add(node)

    for block in sorted(blocks, key=lambda item: item.start):
        if block.start not in visited:
            visit(block.start)
    return tuple(sorted(loops))
