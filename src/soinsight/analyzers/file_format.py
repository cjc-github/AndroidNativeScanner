"""``advanced.file-format``: identify embedded and outer file formats."""

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
from ..infrastructure.formats import scan

ANALYZER_ID = "advanced.file-format"

_DEFAULT_OPTIONS = {
    "max_scan_bytes": 33554432,
    "max_hits": 200,
}

_CATEGORY_LABELS = {
    "archive": "压缩/归档",
    "image": "图像",
    "audio": "音频",
    "document": "文档",
    "mobile": "移动端",
    "executable": "可执行/字节码",
    "data": "数据库/数据",
}


class AdvancedFileFormatAnalyzer(Analyzer):
    """Locate the outer and embedded file formats of the target."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="File Format Analyzer",
        version="1.0.0",
        description="Identify embedded and outer file formats by signature.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="FORMAT_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        hits = scan(blob, max_hits=options["max_hits"])
        sections = _section_ranges(target.real_path)
        formats = [
            _hit_dict(hit, _section_for_offset(sections, hit.offset))
            for hit in hits
        ]

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "scanned_bytes": len(blob),
                "file_size": target.size,
                "scan_truncated": truncated,
                "format_count": len(formats),
                "verified_count": sum(1 for entry in formats if entry["verified"]),
                "outer_format": next(
                    (entry["format"] for entry in formats if entry["offset"] == "0x0"),
                    None,
                ),
                "formats": formats,
                "category_counts": _category_counts(formats),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format format-identification facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 文件格式识别 ===",
            f"外层格式: {data.get('outer_format') or '未识别'}",
            f"命中: {data.get('format_count', 0)} 处"
            f"（结构校验通过 {data.get('verified_count', 0)} 处）",
        ]
        if data.get("scan_truncated"):
            lines.append("注意: 输入已按上限截断，尾部未扫描")
        categories = data.get("category_counts", {})
        if categories:
            summary = "，".join(
                f"{_CATEGORY_LABELS.get(key, key)} {value}"
                for key, value in sorted(categories.items())
            )
            lines.append(f"类别: {summary}")
        formats = data.get("formats", [])
        if formats:
            lines.append("")
            lines.append("命中（按偏移）:")
            for entry in formats[:_TEXT_HIT_LIMIT]:
                section = entry.get("section") or "文件偏移"
                marker = "校验通过" if entry.get("verified") else "仅魔数"
                lines.append(
                    f"  {entry['offset']:>10s} {entry['format']:<16} "
                    f"[{section}] {marker}"
                )
            remaining = len(formats) - _TEXT_HIT_LIMIT
            if remaining > 0:
                lines.append(f"  ... 以及另外 {remaining} 处")
        else:
            lines.append("未识别出已知格式")
        return "\n".join(lines)


_TEXT_HIT_LIMIT = 10


def _hit_dict(hit, section: str | None) -> dict:
    entry = hit.as_dict()
    entry["section"] = section
    entry["outer"] = hit.offset == 0
    return entry


def _section_ranges(path):
    """Map every section's file range when the target is an ELF image."""
    try:
        elf = parse_elf(path)
    except (ElfFormatError, OSError):
        return ()
    return tuple(
        (section.offset, section.offset + section.size, section.name)
        for section in elf.sections
        if section.size > 0
    )


def _section_for_offset(ranges, offset: int) -> str | None:
    for start, end, name in ranges:
        if start <= offset < end:
            return name
    return None


def _category_counts(formats: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in formats:
        counts[entry["category"]] = counts.get(entry["category"], 0) + 1
    return counts


def _read_head(path, limit: int) -> tuple[bytes, bool]:
    with open(path, "rb") as stream:
        blob = stream.read(limit)
    try:
        size = path.stat().st_size
    except OSError:
        size = len(blob)
    return blob, size > len(blob)


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_scan_bytes", "max_hits"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    return resolved
