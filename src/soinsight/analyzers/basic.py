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

_DEFAULT_OPTIONS = {
    "include_sections": True,
    "include_segments": True,
}


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


def _elf_type_machine_is_aarch64(data: dict) -> bool:
    return data.get("machine") == "AArch64"


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
        options = _resolve_options(context)
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
                "has_stack_canary": hardening["has_stack_canary"],
                "has_cfi": hardening["has_cfi"],
                "has_pac": hardening["has_pac"],
                "relro_mode": hardening["relro_mode"],
                "segments": _segment_records(elf) if options["include_segments"] else [],
                "sections": _section_records(elf) if options["include_sections"] else [],
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
            f"栈保护(Canary): {'是' if data.get('has_stack_canary') else '否/未知'}",
            f"CFI: {'是' if data.get('has_cfi') else '否/未知'}",
        ]
        if _elf_type_machine_is_aarch64(data):
            lines.append(f"AArch64 PAC: {'是' if data.get('has_pac') else '否/未知'}")
        else:
            lines.append("AArch64 PAC: 不适用（非 AArch64 目标）")
        return "\n".join(lines)


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and ranges enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get("basic.elf", {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("include_sections", "include_segments"):
        if key in declared:
            resolved[key] = bool(declared[key])
    return resolved


def _segment_records(elf) -> list[dict]:
    """One record per program header, with its permission bits spelled out."""
    records: list[dict] = []
    for segment in elf.program_headers:
        records.append(
            {
                "type": segment.type,
                "flags": _segment_flags(segment.flags),
                "offset": hex(segment.offset),
                "vaddr": hex(segment.virtual_address),
                "file_size": segment.file_size,
                "memory_size": segment.memory_size,
                "alignment": segment.alignment,
            }
        )
    return records


def _segment_flags(flags: int) -> str:
    """Render the program-header permission bits as ``rwx``."""
    return "".join(
        (
            "r" if flags & 0x4 else "-",
            "w" if flags & 0x2 else "-",
            "x" if flags & 0x1 else "-",
        )
    )


def _section_records(elf) -> list[dict]:
    """One record per section header, with its attribute flags spelled out."""
    records: list[dict] = []
    for section in elf.sections:
        records.append(
            {
                "name": section.name,
                "type": section.type,
                "flags": _section_flags(section.flags),
                "address": hex(section.address),
                "offset": hex(section.offset),
                "size": section.size,
            }
        )
    return records


def _section_flags(flags: int) -> str:
    """Render the section attribute flags as a short attribute string."""
    letters = []
    if flags & 0x1:
        letters.append("w")
    if flags & 0x2:
        letters.append("a")
    if flags & 0x4:
        letters.append("x")
    if flags & 0x10:
        letters.append("m")
    if flags & 0x20:
        letters.append("s")
    if flags & 0x400:
        letters.append("t")
    return "".join(letters)
