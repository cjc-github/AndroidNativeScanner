"""``advanced.obfuscation``: report obfuscation and packing evidence."""

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
from ..infrastructure.obfuscation import scan_sections

ANALYZER_ID = "advanced.obfuscation"

_DEFAULT_OPTIONS = {
    "max_scan_bytes": 33554432,
    "max_symbols": 5000,
    "entropy_threshold": 7.0,
    "max_section_bytes": 8388608,
}

_CATEGORY_LABELS = {
    "packer": "加壳",
    "protector": "保护器",
    "obfuscator": "混淆器",
    "packing": "可疑高熵",
}

_STRENGTH_LABELS = {"single": "单一证据", "corroborated": "多源印证"}


class AdvancedObfuscationAnalyzer(Analyzer):
    """Report obfuscation and packing evidence of the image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Obfuscation Analyzer",
        version="1.0.0",
        description="Report obfuscation and packing evidence.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="OBFUSCATION_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        elf = _optional_elf(target.real_path)
        section_blobs = _section_blobs(target.real_path, elf, options)
        symbols = _symbol_names(elf, options["max_symbols"])
        hits = scan_sections(
            section_blobs,
            symbols,
            entropy_threshold=options["entropy_threshold"],
        )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "scanned_bytes": len(blob),
                "file_size": target.size,
                "scan_truncated": truncated,
                "symbol_count": len(symbols),
                "section_count": len(section_blobs),
                "signal_count": len(hits),
                "corroborated_count": sum(
                    1 for item in hits if item.strength == "corroborated"
                ),
                "signals": [
                    {
                        "signal": item.signal,
                        "category": item.category,
                        "strength": item.strength,
                        "evidence": [
                            {"kind": ev.kind, "detail": ev.detail}
                            for ev in item.evidence
                        ],
                    }
                    for item in hits
                ],
                "categories": _category_counts(hits),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format obfuscation evidence as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 混淆识别 ===",
            f"信号: {data.get('signal_count', 0)} 条"
            f"（多源印证 {data.get('corroborated_count', 0)} 条）",
        ]
        if data.get("scan_truncated"):
            lines.append("注意: 输入已按上限截断，尾部未扫描")
        categories = data.get("categories", {})
        if categories:
            summary = "，".join(
                f"{_CATEGORY_LABELS.get(key, key)} {value}"
                for key, value in sorted(categories.items())
            )
            lines.append(f"类别: {summary}")
        signals = data.get("signals", [])
        if signals:
            lines.append("")
            lines.append("信号明细:")
            for item in signals:
                category = _CATEGORY_LABELS.get(item["category"], item["category"])
                strength = _STRENGTH_LABELS.get(item["strength"], item["strength"])
                lines.append(
                    f"  {item['signal']:<16} [{category}] {strength}"
                )
                for evidence in item["evidence"][:4]:
                    lines.append(f"      - {evidence['detail']}")
        else:
            lines.append("未发现已知混淆信号")
        return "\n".join(lines)


def _category_counts(hits) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in hits:
        counts[item.category] = counts.get(item.category, 0) + 1
    return counts


def _section_blobs(path, elf, options: dict) -> tuple[tuple[str, bytes], ...]:
    """Read the file bytes backing each non-empty, sized section."""
    if elf is None:
        return ()
    blobs: list[tuple[str, bytes]] = []
    for section in elf.sections:
        if section.size <= 0:
            continue
        size = min(section.size, options["max_section_bytes"])
        blob = _read_section(path, section.offset, size)
        if blob:
            blobs.append((section.name, blob))
    return tuple(blobs)


def _read_section(path, offset: int, size: int) -> bytes:
    with open(path, "rb") as stream:
        stream.seek(offset)
        return stream.read(size)


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
    for key in ("max_scan_bytes", "max_symbols", "entropy_threshold", "max_section_bytes"):
        if key in declared:
            try:
                value = float(declared[key]) if key == "entropy_threshold" else int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            if key == "entropy_threshold":
                resolved[key] = max(0.0, min(value, 8.0))
            else:
                resolved[key] = max(1, int(value))
    return resolved
