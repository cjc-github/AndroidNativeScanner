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

# ELF e_flags bit: big-endian data with big-endian instruction encoding.
EF_ARM_BE8 = 0x00800000

# ELF e_machine name -> (family, Capstone architecture constant, bit width).
#
# The width is ``None`` when the machine says nothing about it (MIPS and
# PowerPC exist in both), and fixed when it does: e_machine 3 is 32-bit x86
# and e_machine 62 is 64-bit, whatever the ELF class claims.
_ARCHITECTURES = {
    "x86": ("x86", "CS_ARCH_X86", 32),
    "Intel 80386": ("x86", "CS_ARCH_X86", 32),
    "x86-64": ("x86", "CS_ARCH_X86", 64),
    "ARM": ("arm", "CS_ARCH_ARM", 32),
    "AArch64": ("aarch64", "CS_ARCH_ARM64", 64),
    "MIPS": ("mips", "CS_ARCH_MIPS", None),
    "PowerPC": ("ppc", "CS_ARCH_PPC", 32),
    "PowerPC64": ("ppc", "CS_ARCH_PPC", 64),
    "S390": ("sysz", "CS_ARCH_SYSZ", 64),
    "SuperH": ("sh", "CS_ARCH_SH", 32),
    "SPARC": ("sparc", "CS_ARCH_SPARC", 32),
    "SPARCv9": ("sparc", "CS_ARCH_SPARC", 64),
    "68K": ("m68k", "CS_ARCH_M68K", 32),
    "RISC-V": ("riscv", "CS_ARCH_RISCV", None),
    # IA-64 has no Capstone architecture; it stays unsupported on purpose.
}


@dataclass(frozen=True)
class DecoderProfile:
    """How one image must be decoded."""

    arch: int
    """The Capstone architecture constant."""

    mode: int
    """The base Capstone mode."""

    family: str
    """Short family name: ``x86``, ``arm``, ``aarch64``, ``mips``, ``ppc`` ..."""

    thumb_capable: bool = False
    """True for ARM, where the mode depends on the function being decoded."""

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


def capstone_module():
    """Return the imported Capstone module, or ``None`` when unavailable.

    Infrastructure modules that need Capstone's *detail* mode (operand
    access) share this loader instead of importing Capstone on their own.
    """
    return _load_capstone()


def capstone_version() -> str | None:
    """Return the installed Capstone version, or ``None`` when unavailable."""
    module = _load_capstone()
    return module.__version__ if module is not None else None


def decoder_profile(elf: ElfFile) -> DecoderProfile | None:
    """Build the decoder profile of an image, or ``None`` when unsupported.

    Returns ``None`` when the machine is unsupported or Capstone is absent,
    so callers fall back to boundary facts without decoding.
    """
    module = _load_capstone()
    if module is None:
        return None
    entry = _ARCHITECTURES.get(elf.header.machine)
    if entry is None:
        return None
    family, arch_name, width = entry
    arch = getattr(module, arch_name, None)
    if arch is None:
        return None

    is64 = elf.header.elf_class == "ELF64"
    if width is not None:
        is64 = width == 64
    big_endian = elf.header.endianness == "big"
    if elf.header.machine == "ARM" and elf.header.flags & EF_ARM_BE8:
        # BE8 keeps little-endian data with big-endian instruction encoding.
        big_endian = True
    mode = _mode_for(module, family, is64=is64, big_endian=big_endian)
    if mode is None:
        return None
    return DecoderProfile(
        arch=arch,
        mode=mode,
        family=family,
        thumb_capable=(family == "arm"),
    )


def _mode_for(module, family: str, *, is64: bool, big_endian: bool) -> int | None:
    """The Capstone mode for one architecture, bit width and byte order."""
    endian = module.CS_MODE_BIG_ENDIAN if big_endian else module.CS_MODE_LITTLE_ENDIAN
    if family == "x86":
        return module.CS_MODE_64 if is64 else module.CS_MODE_32
    if family in ("arm", "aarch64"):
        return endian
    if family == "mips":
        width = module.CS_MODE_MIPS64 if is64 else module.CS_MODE_MIPS32
        return width | endian
    if family == "ppc":
        width = module.CS_MODE_64 if is64 else module.CS_MODE_32
        return width | endian
    if family in ("sysz", "sparc"):
        return module.CS_MODE_BIG_ENDIAN
    if family == "sh":
        return module.CS_MODE_SH4 | module.CS_MODE_LITTLE_ENDIAN
    if family == "m68k":
        return module.CS_MODE_BIG_ENDIAN | module.CS_MODE_M68K_040
    if family == "riscv":
        return module.CS_MODE_RISCV64 if is64 else module.CS_MODE_RISCV32
    return None


def mode_for_address(profile: DecoderProfile, address: int) -> int:
    """The mode to decode the function at ``address`` with.

    ARM needs the per-function decision: the symbol value of a Thumb
    function carries bit 0, and the code starts one byte lower. The address
    passed here must be the raw symbol value -- the normalized one has the
    Thumb bit already cleared.
    """
    if profile.thumb_capable and address & 1:
        return profile.mode | _module_constant("CS_MODE_THUMB", 16)
    return profile.mode


def normalize_function_address(profile: DecoderProfile | None, address: int) -> int:
    """The address a function actually starts at.

    For ARM the symbol value of a Thumb function has bit 0 set; the code
    starts one byte lower.
    """
    if profile is not None and profile.thumb_capable:
        return address & ~1
    return address


def _module_constant(name: str, fallback: int) -> int:
    module = _load_capstone()
    if module is None:
        return fallback
    return getattr(module, name, fallback)


def arch_name(machine: str) -> str | None:
    """Return the short architecture name used for prologue scanning."""
    entry = _ARCHITECTURES.get(machine)
    return entry[0] if entry else None


def resolvable_families() -> frozenset[str]:
    """The architecture families whose references the xref layer can resolve.

    Every family in the decoder table can be disassembled, but the reference
    resolution is written per instruction set, so only these have one.
    """
    return frozenset({"x86", "arm", "aarch64"})


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


def function_boundaries(
    elf: ElfFile,
    blob: bytes,
    regions,
    profile: "DecoderProfile | None",
) -> tuple[tuple[int, str, int, str, int], ...]:
    """Function boundaries of an image, with the raw address of each.

    Each record is ``(address, name, size, source, raw_address)``.  The raw
    address keeps the symbol value that carried the Thumb bit; the address is
    the normalized one, where the code actually starts.

    Boundaries come from the symbol table first, then from a prologue scan:
    a byte pattern for x86-64 and AArch64, and the decoder for ARM, whose
    encodings a byte pattern cannot tell apart.
    """
    starts: list[tuple[int, str, int, str, int]] = []
    known: set[int] = set()
    for name, address, size, table in symbol_functions(elf):
        real = normalize_function_address(profile, address)
        starts.append((real, name, size, "symbols", address))
        known.add(real)

    arch = profile.family if profile is not None else None
    if arch is not None:
        for region in regions:
            window = blob[region.offset : region.offset + region.size]
            if not window:
                continue
            if arch == "arm":
                from .arm_entries import arm_entry_candidates

                for candidate in arm_entry_candidates(
                    window, region.address, profile.arch, arm_modes(profile)
                ):
                    if candidate.address in known:
                        continue
                    raw = candidate.address | (1 if candidate.thumb else 0)
                    starts.append(
                        (
                            candidate.address,
                            f"sub_{candidate.address:x}",
                            0,
                            "prologue",
                            raw,
                        )
                    )
                    known.add(candidate.address)
                continue
            step = 4 if arch == "aarch64" else 1
            for address in prologue_starts(
                window, region.address, arch, step, known
            ):
                starts.append((address, f"sub_{address:x}", 0, "prologue", address))
                known.add(address)

    starts.sort(key=lambda item: item[0])
    return tuple(starts)


def arm_modes(profile: "DecoderProfile") -> tuple[int, ...]:
    """The Capstone modes to try on ARM: the base mode and Thumb."""
    return (profile.mode, profile.mode | _module_constant("CS_MODE_THUMB", 16))


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
        # ARM is absent on purpose: a byte-level scan cannot tell a Thumb
        # prologue from Thumb-2 data, so the decoder decides there.
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
