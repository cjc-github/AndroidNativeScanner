"""Built-in Basic domain analyzers."""

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.elf import ElfFormatError, parse_elf


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


def _read_magic(path, length: int = 8) -> bytes:
    with open(path, "rb") as stream:
        return stream.read(length)


def _detect_format(magic: bytes) -> str:
    if magic.startswith(b"\x7fELF"):
        return "elf"
    return "unknown"


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
        try:
            elf = parse_elf(target.real_path)
        except ElfFormatError as exc:
            return AnalysisResult(
                analyzer_id=self.metadata.id,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[
                    Diagnostic(
                        code="INVALID_ELF",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                        analyzer_id=self.metadata.id,
                    )
                ],
            )

        header = elf.header
        hardening = elf.hardening_facts()
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "elf_class": header.elf_class,
                "endianness": header.endianness,
                "type": header.type,
                "machine": header.machine,
                "entry_point": hex(header.entry_point),
                "program_header_count": header.program_header_count,
                "section_header_count": header.section_header_count,
                "has_gnu_relro": hardening["has_gnu_relro"],
                "executable_stack": hardening["executable_stack"],
            },
        )
