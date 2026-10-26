"""Built-in Advanced domain analyzers."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerKind, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.elf import ElfFormatError, parse_elf
from ..infrastructure.strings import extract_strings
from ..infrastructure.strings.classify import _BASE64_MAX_BYTES, classify_string

ANALYZER_ID = "advanced.strings"

_CATEGORIES = ("url", "sensitive", "base64")
_CATEGORY_LABELS = {"url": "URL", "sensitive": "敏感字符串", "base64": "Base64"}

_DEFAULT_OPTIONS = {
    "min_length": 4,
    "max_strings": 1000,
    "max_hits_per_category": 100,
    "max_scan_bytes": 33554432,
    "classify": True,
}


class AdvancedStringsAnalyzer(Analyzer):
    """Extract printable strings with offsets and classify them into facts.

    The analyzer works on any file: ELF is optional and only supplies the
    section attribution of an offset. It reports facts, never findings;
    severity judgment lives in the built-in ``security.*`` rules.
    """

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Strings Analyzer",
        version="1.0.0",
        description="Extract, locate and classify printable strings.",
        kind=AnalyzerKind.COLLECTOR,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, scan_truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if scan_truncated:
            diagnostics.append(
                Diagnostic(
                    code="STRINGS_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        elf = _optional_elf(target.real_path)
        extraction = extract_strings(
            blob, min_length=options["min_length"]
        )

        strings, strings_truncated = _string_records(
            extraction.entries, elf, options["max_strings"]
        )
        if strings_truncated:
            diagnostics.append(
                Diagnostic(
                    code="STRINGS_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The string list was truncated to {options['max_strings']} "
                        "entries; counts describe the full scan."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        classified = _classify_facts(
            extraction.entries, elf, options
        )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "min_length": options["min_length"],
                "classify": options["classify"],
                "scan_truncated": scan_truncated,
                "scanned_bytes": extraction.scanned_bytes,
                "file_size": target.size,
                "counts": {
                    "unique_strings": extraction.unique_count,
                    "total_strings": extraction.occurrence_count,
                    "strings_reported": len(strings),
                },
                "strings": strings,
                "classified": classified,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format string analysis result as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        counts = data.get("counts", {})
        classified = data.get("classified", {})

        lines = [
            "=== 字符串分析 ===",
            f"字符串总数: {counts.get('total_strings', 0)}",
            f"唯一字符串数: {counts.get('unique_strings', 0)}",
            f"最小长度: {data.get('min_length', 0)}",
            f"扫描字节数: {data.get('scanned_bytes', 0):,}",
            "",
        ]

        # 分类统计
        if data.get("classify"):
            lines.append("=== 字符串分类 ===")
            for category in _CATEGORIES:
                cat_data = classified.get(category, {})
                count = cat_data.get("count", 0)
                truncated = cat_data.get("truncated", False)
                lines.append(f"  {_CATEGORY_LABELS.get(category, category)}: {count}")

                # 显示示例
                hits = cat_data.get("hits", [])[:5]
                for hit in hits:
                    value = hit.get("value", "")
                    if len(value) > 60:
                        value = value[:57] + "..."
                    lines.append(f"    - {value}")

                if truncated:
                    lines.append(f"    ...（已截断）")
            lines.append("")

        # 显示部分字符串样本
        strings = data.get("strings", [])
        if strings:
            lines.append(f"=== 字符串样本（显示前 {min(10, len(strings))} / 共 {len(strings)} 个）===")
            for s in strings[:10]:
                value = s.get("value", "")
                if len(value) > 80:
                    value = value[:77] + "..."
                offset = s.get("offset", "")
                lines.append(f"  [{offset}] {value}")

            if len(strings) > 10:
                lines.append(f"  ... 以及另外 {len(strings) - 10} 个字符串")

        return "\n".join(lines)


def _read_head(path, max_scan_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_scan_bytes`` bytes and say whether the tail exists."""
    with open(path, "rb") as stream:
        blob = stream.read(max(0, max_scan_bytes))
        more = stream.read(1)
    return blob, bool(more)


def _optional_elf(path):
    """Parse the image for section attribution; non-ELF targets have none."""
    try:
        return parse_elf(path)
    except ElfFormatError:
        return None


def _section_of(elf, offset: int) -> str | None:
    """Name the section that contains the byte offset, preferring loaded ones."""
    if elf is None:
        return None
    allocated = None
    for section in elf.sections:
        if section.size <= 0:
            continue
        if section.offset <= offset < section.offset + section.size:
            if section.flags & 0x2:
                return section.name
            if allocated is None:
                allocated = section.name
    return allocated


def _string_records(entries, elf, max_strings: int) -> tuple[list[dict], bool]:
    truncated = len(entries) > max_strings
    records = [
        {
            "value": entry.value,
            "offset": hex(entry.offset),
            "occurrences": entry.occurrences,
            "section": _section_of(elf, entry.offset),
        }
        for entry in entries[:max_strings]
    ]
    return records, truncated


def _classify_facts(entries, elf, options: dict) -> dict[str, dict]:
    """Build per-category fact groups with totals independent of hit limits."""
    totals = {category: 0 for category in _CATEGORIES}
    hits: dict[str, list[dict]] = {category: [] for category in _CATEGORIES}
    if options["classify"]:
        limits = {category: options["max_hits_per_category"] for category in _CATEGORIES}
        for entry in entries:
            if len(entry.value) > _BASE64_MAX_BYTES:
                continue
            for fact in classify_string(entry.value):
                totals[fact.category] += 1
                if len(hits[fact.category]) >= limits[fact.category]:
                    continue
                hit = {
                    "value": fact.value,
                    "offset": hex(entry.offset),
                    "section": _section_of(elf, entry.offset),
                }
                if fact.category == "sensitive":
                    hit["label"] = fact.label
                elif fact.category == "base64":
                    hit["decoded"] = fact.decoded
                hits[fact.category].append(hit)
    return {
        category: {
            "count": totals[category],
            "truncated": totals[category] > len(hits[category]),
            "hits": hits[category],
        }
        for category in _CATEGORIES
    }


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and ranges enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("min_length", "max_strings", "max_hits_per_category", "max_scan_bytes"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    if "classify" in declared:
        resolved["classify"] = bool(declared["classify"])
    return resolved
