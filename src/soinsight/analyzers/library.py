"""``advanced.library``: identify third-party libraries and version clues."""

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
from ..infrastructure.library import identify
from ..infrastructure.strings import extract_strings

ANALYZER_ID = "advanced.library"

_DEFAULT_OPTIONS = {
    "max_scan_bytes": 33554432,
    "max_symbols": 5000,
    "max_strings": 2000,
    "min_length": 4,
}

_FAMILY_LABELS = {
    "runtime": "运行时",
    "crypto": "加密",
    "compression": "压缩",
    "image": "图像/渲染",
    "network": "网络",
    "serialization": "序列化",
    "xml": "XML",
    "media": "媒体",
    "logging": "日志",
}

_STRENGTH_LABELS = {"single": "单一证据", "corroborated": "多源印证"}


class AdvancedLibraryAnalyzer(Analyzer):
    """Identify third-party libraries and their version clues."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Library Analyzer",
        version="1.0.0",
        description="Identify third-party libraries and version clues.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="LIBRARY_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        elf = _optional_elf(target.real_path)
        needed, soname = _dynamic_facts(elf)
        symbol_names = _symbol_names(elf, options["max_symbols"])
        string_values = _string_values(blob, options)
        report = identify(needed, soname, symbol_names, string_values)

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "scanned_bytes": len(blob),
                "file_size": target.size,
                "scan_truncated": truncated,
                "needed_count": len(needed),
                "symbol_count": len(symbol_names),
                "string_count": len(string_values),
                "library_count": len(report.libraries),
                "corroborated_count": report.corroborated_count,
                "libraries": [
                    {
                        "library": item.library,
                        "family": item.family,
                        "strength": item.strength,
                        "evidence": [
                            {"source": ev.source, "detail": ev.detail}
                            for ev in item.evidence
                        ],
                    }
                    for item in report.libraries
                ],
                "families": _family_counts(report),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format library facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 第三方库识别 ===",
            f"证据: 依赖 {data.get('needed_count', 0):,} /"
            f" 符号 {data.get('symbol_count', 0):,} /"
            f" 字符串 {data.get('string_count', 0):,}",
            f"识别: {data.get('library_count', 0)} 个库"
            f"（多源印证 {data.get('corroborated_count', 0)} 个）",
        ]
        if data.get("scan_truncated"):
            lines.append("注意: 输入已按上限截断，尾部未扫描")
        libraries = data.get("libraries", [])
        if libraries:
            lines.append("")
            lines.append("识别结果:")
            for item in libraries:
                family = _FAMILY_LABELS.get(item["family"], item["family"])
                strength = _STRENGTH_LABELS.get(item["strength"], item["strength"])
                lines.append(
                    f"  {item['library']:<16} [{family}] {strength}"
                )
                for evidence in item["evidence"][:4]:
                    lines.append(f"      - {evidence['detail']}")
        else:
            lines.append("未识别出已知第三方库")
        return "\n".join(lines)


def _family_counts(report) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in report.libraries:
        counts[item.family] = counts.get(item.family, 0) + 1
    return counts


def _dynamic_facts(elf):
    if elf is None:
        return (), None
    return tuple(elf.dynamic.needed), elf.dynamic.soname


def _symbol_names(elf, limit: int) -> tuple[str, ...]:
    if elf is None:
        return ()
    names: list[str] = []
    seen: set[str] = set()
    for symbol in elf.symbols:
        if not symbol.name or symbol.name in seen:
            continue
        seen.add(symbol.name)
        names.append(symbol.name)
        if len(names) >= limit:
            break
    return tuple(names)


def _string_values(blob: bytes, options: dict) -> tuple[str, ...]:
    extraction = extract_strings(blob, min_length=options["min_length"])
    return tuple(entry.value for entry in extraction.entries[: options["max_strings"]])


def _read_head(path, limit: int) -> tuple[bytes, bool]:
    with open(path, "rb") as stream:
        blob = stream.read(limit)
    try:
        size = path.stat().st_size
    except OSError:
        size = len(blob)
    return blob, size > len(blob)


def _optional_elf(path):
    try:
        return parse_elf(path)
    except (ElfFormatError, OSError):
        return None


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_scan_bytes", "max_symbols", "max_strings", "min_length"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    return resolved
