"""Built-in Basic domain analyzers."""

from pathlib import Path

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import AnalysisResult, AnalysisStatus, AnalysisTarget


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
