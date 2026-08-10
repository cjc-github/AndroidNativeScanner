"""Built-in Basic domain analyzers."""

import struct
from pathlib import Path

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)


class BasicFileAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="basic.file",
        name="File Analyzer",
        version="1.0.0",
        description="Collect file properties, digest and magic bytes.",
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del context
        magic = _read_magic(target.real_path)
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "path": str(target.path),
                "real_path": str(target.real_path),
                "name": target.name,
                "size": target.size,
                "sha256": target.sha256,
                "magic": magic.hex(),
                "format": _detect_format(magic),
            },
        )


def _read_magic(path: Path, length: int = 8) -> bytes:
    with path.open("rb") as stream:
        return stream.read(length)


def _detect_format(magic: bytes) -> str:
    if magic.startswith(b"\x7fELF"):
        return "elf"
    return "unknown"


_ELF_TYPES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

_ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
}

_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1


def _parse_program_header_hardening(
    path: Path, elf_class: str, endian: str, phoff: int, phnum: int
) -> dict:
    """Return NX/RELRO facts from the program header table, or None if unreadable.

    None means the table is absent or truncated, so callers must not treat the
    absence of a feature as proof of its absence.
    """
    if elf_class not in ("ELF64", "ELF32") or phoff <= 0 or phnum <= 0:
        return {"has_gnu_relro": None, "executable_stack": None}
    prefix = "<" if endian == "little" else ">"
    if elf_class == "ELF64":
        phdr_size, phdr_format = 56, prefix + "IIQQQQQQ"
    else:
        phdr_size, phdr_format = 32, prefix + "IIIIIIII"
    total = phnum * phdr_size
    raw = path.read_bytes()[phoff:phoff + total]
    if len(raw) < total:
        return {"has_gnu_relro": None, "executable_stack": None}
    has_relro = False
    executable_stack = None
    for index in range(phnum):
        p_type, p_flags = struct.unpack_from(
            phdr_format, raw, index * phdr_size
        )[:2]
        if p_type == _PT_GNU_RELRO:
            has_relro = True
        elif p_type == _PT_GNU_STACK:
            executable_stack = bool(p_flags & _PF_X)
    return {"has_gnu_relro": has_relro, "executable_stack": executable_stack}


class BasicElfAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="basic.elf",
        name="ELF Header Analyzer",
        version="1.0.0",
        description="Parse ELF identification and header fields.",
        requires=("basic.file",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del context
        data = target.real_path.read_bytes()[:64]
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return AnalysisResult(
                analyzer_id=self.metadata.id,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[Diagnostic(
                    code="INVALID_ELF",
                    level=DiagnosticLevel.ERROR,
                    message="Target is not a valid ELF file",
                    analyzer_id=self.metadata.id,
                )],
            )
        elf_class = "ELF64" if data[4] == 2 else "ELF32" if data[4] == 1 else "unknown"
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        prefix = "<" if endian == "little" else ">"
        if elf_class == "ELF64":
            fields = struct.unpack(prefix + "HHIQQQIHHHHHH", data[16:64])
            e_type, e_machine, _, e_entry, e_phoff, _, _, _, _, e_phnum, _, e_shnum, _ = fields
        else:
            fields = struct.unpack(prefix + "HHIIIIIHHHHHH", data[16:52])
            e_type, e_machine, _, e_entry, e_phoff, _, _, _, _, e_phnum, _, e_shnum, _ = fields
        hardening = _parse_program_header_hardening(
            target.real_path, elf_class, endian, e_phoff, e_phnum
        )
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "elf_class": elf_class,
                "endianness": endian,
                "type": _ELF_TYPES.get(e_type, str(e_type)),
                "machine": _ELF_MACHINES.get(e_machine, str(e_machine)),
                "entry_point": hex(e_entry),
                "program_header_count": e_phnum,
                "section_header_count": e_shnum,
                "has_gnu_relro": hardening["has_gnu_relro"],
                "executable_stack": hardening["executable_stack"],
            },
        )
