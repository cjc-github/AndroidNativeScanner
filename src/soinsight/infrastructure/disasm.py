"""Disassembly layer over Capstone with graceful degradation.

The layer decodes executable sections of parsed ELF images into instructions
and recovers function boundaries. Boundaries come from the symbol table
first; symbol-less gaps are scanned for common prologues. Capstone is an
optional dependency like ``cpp_demangle``: when it is missing the boundary
facts still work, but no instructions are decoded.
"""

import importlib
import importlib.util
from dataclasses import dataclass

from .elf import ElfFile, SectionHeader

_SPEC = importlib.util.find_spec("capstone")
_MODULE = None

# ELF e_machine name -> (short arch name, capstone arch constant, mode name).
_ARCHITECTURES = {
    "x86-64": ("x86", "CS_ARCH_X86", "CS_MODE_64"),
    "AArch64": ("aarch64", "CS_ARCH_ARM64", "CS_MODE_LITTLE_ENDIAN"),
    "ARM": ("arm", "CS_ARCH_ARM", "CS_MODE_LITTLE_ENDIAN"),
    "Intel 80386": ("x86", "CS_ARCH_X86", "CS_MODE_32"),
}

X86_PROLOGUE_PATTERNS = (b"\xf3\x0f\x1e\xfa", b"\x55\x48\x89\xe5")


@dataclass(frozen=True)
class DecodedInstruction:
    """One decoded instruction within an executable region."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str


def _load_capstone():
    """Import and cache Capstone; returns ``None`` when it is unavailable."""
    global _MODULE
    if _SPEC is None:
        return None
    if _MODULE is None:
        # A plain import is required: capstone's __init__ looks itself up in
        # sys.modules, which module_from_spec() does not populate.
        _MODULE = importlib.import_module("capstone")
    return _MODULE


def capstone_version() -> str | None:
    """Return the installed Capstone version, or ``None`` when unavailable."""
    module = _load_capstone()
    return module.__version__ if module is not None else None


def decode_architecture(machine: str) -> tuple[str, int] | None:
    """Map an ELF ``e_machine`` name to ``(capstone arch, capstone mode)``.

    Returns ``None`` when the machine is unsupported or Capstone is absent,
    so callers fall back to boundary facts without decoding.
    """
    pair = _ARCHITECTURES.get(machine)
    if pair is None:
        return None
    module = _load_capstone()
    if module is None:
        return None
    _, arch_constant, mode_name = pair
    return getattr(module, arch_constant), getattr(module, mode_name)


def arch_name(machine: str) -> str | None:
    """Return the short architecture name used for prologue scanning."""
    pair = _ARCHITECTURES.get(machine)
    return pair[0] if pair else None


def is_aarch64_blob_prologue(blob: bytes) -> bool:
    """Common AArch64 prologues: ``stp x29, x30, [sp, ...]`` or ``sub sp``."""
    if len(blob) < 4:
        return False
    stp = blob[0] == 0xFD and blob[1] == 0x7B and blob[3] == 0xA9
    sub_sp = blob[0] == 0xFF and (blob[1] & 0x03) == 0x03 and blob[3] == 0xD1
    return stp or sub_sp


def executable_sections(elf: ElfFile) -> tuple[SectionHeader, ...]:
    """Executable, non-empty sections with a virtual address."""
    return tuple(
        section
        for section in elf.sections
        if section.flags & 0x4 and section.size > 0 and section.address > 0
    )


def symbol_functions(elf: ElfFile) -> tuple[tuple[str, int, int, str], ...]:
    """Defined function symbols as ``(name, address, size, table)``.

    Duplicate address/size pairs collapse: the regular ``.symtab`` entry
    (usually carrying the unmangled name) wins over ``.dynsym``.
    """
    bounds: dict[tuple[int, int], tuple[str, int, int, str]] = {}
    for name, address, size, table in sorted(
        (s.name, s.value, s.size, s.table)
        for s in elf.symbols
        if s.is_function and s.is_defined and s.value > 0
    ):
        existing = bounds.get((address, size))
        if existing is None or (table == ".symtab" and existing[3] != ".symtab"):
            bounds[(address, size)] = (name, address, size, table)
    return tuple(bounds[key] for key in sorted(bounds))


def prologue_starts(
    blob: bytes,
    region_address: int,
    arch: str,
    step: int,
    exclude: set[int],
) -> tuple[int, ...]:
    """Scan a byte region for function prologues, skipping known starts."""
    starts: list[int] = []
    for index in range(0, max(0, len(blob) - 3), step):
        address = region_address + index
        if address in exclude:
            continue
        hit = False
        if arch == "x86":
            hit = any(
                blob[index : index + len(pattern)] == pattern
                for pattern in X86_PROLOGUE_PATTERNS
            )
        elif arch == "aarch64":
            hit = is_aarch64_blob_prologue(blob[index : index + 4])
        if hit:
            starts.append(address)
    return tuple(starts)


def decode_bytes(
    blob: bytes, start_address: int, arch: int, mode: int
) -> tuple[DecodedInstruction, ...]:
    """Decode a byte range with Capstone; stops at the first invalid byte."""
    module = _load_capstone()
    if module is None:
        return ()
    engine = module.Cs(arch, mode)
    decoded: list[DecodedInstruction] = []
    for ins in engine.disasm(blob, start_address):
        decoded.append(
            DecodedInstruction(
                address=ins.address,
                size=ins.size,
                mnemonic=ins.mnemonic,
                op_str=ins.op_str,
                bytes_hex=ins.bytes.hex(),
            )
        )
    return tuple(decoded)
