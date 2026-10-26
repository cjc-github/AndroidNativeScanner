"""Built-in Basic domain analyzers."""

from typing import Optional

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

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format file analysis result as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        lines = [
            "=== 文件信息 ===",
            f"路径: {data.get('path', 'N/A')}",
            f"真实路径: {data.get('real_path', 'N/A')}",
            f"文件名: {data.get('name', 'N/A')}",
            f"大小: {data.get('size', 0):,} 字节",
            f"SHA-256: {data.get('sha256', 'N/A')}",
            f"Magic: {data.get('magic', 'N/A')}",
            f"格式: {data.get('format', 'unknown')}",
        ]
        return "\n".join(lines)


def _read_magic(path, length: int = 8) -> bytes:
    with open(path, "rb") as stream:
        return stream.read(length)


def _detect_format(magic: bytes) -> str:
    if magic.startswith(b"\x7fELF"):
        return "elf"
    return "unknown"


# ELF 头字段值的中文说明（仅用于文本化结果，data 字段保持原值）
_ENDIANNESS_LABELS = {"little": "小端（little-endian）", "big": "大端（big-endian）"}
_ELF_TYPE_LABELS = {
    "DYN": "DYN（共享对象 / PIE）",
    "EXEC": "EXEC（可执行文件，非 PIE）",
    "REL": "REL（可重定位文件）",
    "CORE": "CORE（核心转储）",
}


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

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format ELF analysis result as text."""
        if result.status == AnalysisStatus.FAILED:
            return "=== ELF 分析失败 ==="

        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        elf_type = data.get('type', 'N/A')
        lines = [
            "=== ELF 头信息 ===",
            f"类别: {data.get('elf_class', 'N/A')}",
            f"端序: {_ENDIANNESS_LABELS.get(data.get('endianness'), data.get('endianness', 'N/A'))}",
            f"类型: {_ELF_TYPE_LABELS.get(elf_type, elf_type)}",
            f"机器: {data.get('machine', 'N/A')}",
            f"入口点: {data.get('entry_point', 'N/A')}",
            f"程序头数量: {data.get('program_header_count', 0)}",
            f"节头数量: {data.get('section_header_count', 0)}",
            "",
            "=== 安全加固 ===",
            f"GNU RELRO: {'是' if data.get('has_gnu_relro') else '否'}",
            f"栈可执行: {'是' if data.get('executable_stack') else '否'}",
        ]
        return "\n".join(lines)
