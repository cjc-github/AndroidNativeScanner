"""Call-graph construction over decoded instructions.

A call edge is only reported when its target is provable. Direct calls into
the image resolve through the symbol table; calls into a PLT stub resolve
through the stub's GOT slot, which is matched against ``.rela.*`` so the
imported symbol name is recovered. Everything else is an ``indirect`` edge
with no callee, never a guess.

The PLT stub shapes differ per architecture:

* x86-64 stubs end in ``jmp qword ptr [rip + disp]`` (the GOT slot is
  ``next_instruction_address + disp``);
* AArch64 stubs are ``adrp x16, page; ldr x17, [x16, #off]; br x17`` (the GOT
  slot is ``page + off``).

Both are read from the stub itself rather than assuming a fixed stride, which
keeps the resolver correct for PLT0, ``.plt.sec`` and IRELATIVE layouts.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .cfg import direct_target
from .elf import ElfFile, SectionHeader, Symbol

_CALLS = frozenset({"call", "bl", "blr"})
_RELA, _REL = 4, 9


@dataclass(frozen=True)
class CallEdge:
    """One call site: caller address, callee and how it was resolved."""

    caller: int
    callee: int | None
    callee_name: str | None
    kind: str  # local | import | indirect


@dataclass(frozen=True)
class CallGraph:
    """Call edges plus a reverse index for one image."""

    edges: tuple[CallEdge, ...]
    callers_of: tuple[tuple[int, tuple[int, ...]], ...]

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def indirect_count(self) -> int:
        return sum(1 for edge in self.edges if edge.kind == "indirect")


def relocation_slots(data: bytes, elf: ElfFile) -> dict[int, int]:
    """Map a relocation slot address to the symbol index it refers to."""
    slots: dict[int, int] = {}
    for section in elf.sections:
        if section.type_value not in (_RELA, _REL):
            continue
        if not (section.name.startswith(".rela") or section.name.startswith(".rel")):
            continue
        for offset, symbol_index in _read_relocations(data, section, elf):
            slots[offset] = symbol_index
    return slots


def _read_relocations(
    data: bytes, section: SectionHeader, elf: ElfFile
) -> list[tuple[int, int]]:
    """Decode one ``.rela``/``.rel`` section into ``(offset, symbol index)``."""
    is64 = elf.is_64bit
    little = elf.header.endianness == "little"
    prefix = "<" if little else ">"
    is_rela = section.type_value == _RELA
    entry_size = section.entry_size or (24 if is_rela else 16)
    if entry_size <= 0 or section.size <= 0:
        return []
    count = section.size // entry_size
    start = section.offset
    end = start + count * entry_size
    if start < 0 or end > len(data):
        return []

    entries: list[tuple[int, int]] = []
    for index in range(count):
        base = start + index * entry_size
        if is64:
            offset, info = struct.unpack_from(prefix + "QQ", data, base)[:2]
            symbol_index = info >> 32
        else:
            offset, info = struct.unpack_from(prefix + "II", data, base)
            symbol_index = info >> 8
        entries.append((offset, symbol_index))
    return entries


def _symbol_name(symbols: tuple[Symbol, ...], index: int) -> str | None:
    if not 0 <= index < len(symbols):
        return None
    name = symbols[index].name
    return name or None


def _rip_target(operands: str, next_address: int) -> int | None:
    """GOT address of ``jmp qword ptr [rip + disp]``."""
    index = operands.find("rip")
    if index < 0:
        return None
    tail = operands[index + 3 :]
    sign = 1
    for position, char in enumerate(tail):
        if char == "+":
            tail = tail[position + 1 :]
            break
        if char == "-":
            sign = -1
            tail = tail[position + 1 :]
            break
    try:
        displacement = int(tail.split("]")[0].strip(), 0)
    except ValueError:
        return None
    return next_address + sign * displacement


def _adrp_ldr_target(instructions, position: int) -> int | None:
    """GOT address of an AArch64 ``adrp``/``ldr`` pair ending at ``position``.

    ``position`` points at the ``ldr``; the ``adrp`` is expected immediately
    before it.
    """
    if position < 1:
        return None
    adrp = instructions[position - 1]
    if adrp[2] != "adrp":
        return None
    try:
        page = int(adrp[3].split(",")[-1].strip().lstrip("#"), 0)
    except ValueError:
        return None
    ldr = instructions[position]
    if ldr[2] != "ldr":
        return None
    operands = ldr[3]
    offset = 0
    if "#" in operands:
        try:
            offset = int(operands.rsplit("#", 1)[1].split("]")[0].strip(), 0)
        except ValueError:
            offset = 0
    return page + offset


def plt_imports(data: bytes, elf: ElfFile, decode) -> dict[int, str]:
    """Map each PLT stub address to the imported symbol it dispatches to.

    ``decode(machine)`` returns the Capstone ``(arch, mode)`` pair or ``None``.
    """
    slots = relocation_slots(data, elf)
    if not slots:
        return {}
    plt = next(
        (section for section in elf.sections if section.name in (".plt", ".plt.sec")),
        None,
    )
    if plt is None or plt.offset < 0 or plt.offset + plt.size > len(data):
        return {}
    arch_pair = decode(elf.header.machine)
    if arch_pair is None:
        return {}

    from . import disasm

    blob = data[plt.offset : plt.offset + plt.size]
    instructions = [
        (item.address, item.size, item.mnemonic, item.op_str)
        for item in disasm.decode_bytes(blob, plt.address, arch_pair[0], arch_pair[1])
    ]

    symbols = elf.symbols
    imports: dict[int, str] = {}
    for position, item in enumerate(instructions):
        address, size, mnemonic, operands = item
        if mnemonic == "jmp":
            # x86-64 lazy stub: the jmp is the stub's first instruction.
            target = _rip_target(operands, address + size)
            start = address
        elif mnemonic == "ldr":
            # AArch64 stub: adrp/ldr/add/br, so the adrp starts the stub.
            target = _adrp_ldr_target(instructions, position)
            start = _stub_start(instructions, position)
        else:
            continue
        if target is None:
            continue
        name = _symbol_name(symbols, slots.get(target, -1))
        if name is None:
            # PLT0 dispatches to a slot no relocation claims; it is not an
            # import stub and must not consume one.
            continue
        imports[start] = name
    return imports


def _stub_start(instructions, position: int) -> int:
    """First instruction of the stub whose ``ldr`` sits at ``position``."""
    start = instructions[position][0]
    for index in range(position - 1, -1, -1):
        mnemonic = instructions[index][2]
        if mnemonic in ("br", "nop", "ldr"):
            break
        start = instructions[index][0]
    return start


def _symbol_at(symbols: tuple[Symbol, ...], address: int) -> str | None:
    """Name of the defined function symbol whose range covers ``address``."""
    best: Symbol | None = None
    for symbol in symbols:
        if not (symbol.is_function and symbol.is_defined and symbol.value > 0):
            continue
        if symbol.value <= address < symbol.value + max(symbol.size, 1):
            if best is None or symbol.value > best.value:
                best = symbol
    return best.name if best is not None else None


def _function_bytes(data: bytes, elf: ElfFile, address: int, size: int) -> bytes:
    """File bytes for ``[address, address+size)`` mapped through a code section."""
    for section in elf.sections:
        if not (section.flags & 0x4) or section.size <= 0:
            continue
        if section.address <= address < section.address + section.size:
            offset = section.offset + (address - section.address)
            available = min(size, section.address + section.size - address)
            if offset < 0 or offset + available > len(data):
                return b""
            return data[offset : offset + available]
    return b""


def build_call_graph(
    data: bytes,
    elf: ElfFile,
    functions,
    decode,
) -> CallGraph:
    """Resolve every call site in ``functions`` into a call edge.

    ``functions`` yields ``(name, address, size, source)`` bounds and ``decode``
    is the architecture decoder, so the caller controls the instruction source.
    """
    symbols = elf.symbols
    function_starts = {address: name for name, address, _size, _source in functions}
    imports = plt_imports(data, elf, decode)
    arch_pair = decode(elf.header.machine)
    if arch_pair is None:
        return CallGraph((), ())

    from . import disasm

    edges: list[CallEdge] = []
    callers: dict[int, set[int]] = {}
    for name, address, size, _source in functions:
        if size <= 0:
            continue
        blob = _function_bytes(data, elf, address, size)
        if not blob:
            continue
        for item in disasm.decode_bytes(blob, address, arch_pair[0], arch_pair[1]):
            if item.mnemonic not in _CALLS:
                continue
            edge = _resolve_call(
                item.address, item.op_str, function_starts, imports, symbols
            )
            edges.append(edge)
            if edge.callee is not None:
                callers.setdefault(edge.callee, set()).add(address)

    ordered = tuple(
        (target, tuple(sorted(sources))) for target, sources in sorted(callers.items())
    )
    return CallGraph(tuple(edges), ordered)


def _resolve_call(
    address: int,
    operands: str,
    function_starts: dict[int, str],
    imports: dict[int, str],
    symbols: tuple[Symbol, ...],
) -> CallEdge:
    """Classify one call site without guessing an unresolvable target."""
    target = direct_target(operands)
    if target is None:
        return CallEdge(address, None, None, "indirect")
    if target in imports:
        return CallEdge(address, target, imports[target], "import")
    if target in function_starts:
        return CallEdge(address, target, function_starts[target], "local")
    name = _symbol_at(symbols, target)
    if name is not None:
        return CallEdge(address, target, name, "local")
    return CallEdge(address, target, None, "indirect")
