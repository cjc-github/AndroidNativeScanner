"""``advanced.algorithm``: identify algorithms from combined evidence."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.algorithm import identify
from ..infrastructure.constants import scan
from ..infrastructure.elf import ElfFormatError, parse_elf
from ..infrastructure.strings import extract_strings

ANALYZER_ID = "advanced.algorithm"

_DEFAULT_OPTIONS = {
    "max_scan_bytes": 33554432,
    "max_symbols": 5000,
    "max_strings": 2000,
    "min_length": 4,
}

_FAMILY_LABELS = {
    "cipher": "加密",
    "hash": "哈希",
    "kdf": "密钥派生",
    "compression": "压缩",
    "encoding": "编码",
    "checksum": "校验",
    "library": "库",
}

_STRENGTH_LABELS = {"single": "单一证据", "corroborated": "多源印证"}


class AdvancedAlgorithmAnalyzer(Analyzer):
    """Cross-check constants, symbols and strings into algorithm judgements."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Algorithm Analyzer",
        version="1.0.0",
        description="Identify cryptographic, hash and compression algorithms.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="ALGORITHM_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        elf = _optional_elf(target.real_path)
        constant_hits = scan(blob)
        symbol_names = _symbol_names(elf, options["max_symbols"])
        string_values = _string_values(blob, options)

        report = identify(constant_hits, symbol_names, string_values)

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "scanned_bytes": len(blob),
                "file_size": target.size,
                "scan_truncated": truncated,
                "constant_count": len(constant_hits),
                "symbol_count": len(symbol_names),
                "string_count": len(string_values),
                "algorithm_count": len(report.algorithms),
                "corroborated_count": report.corroborated_count,
                "algorithms": [
                    {
                        "algorithm": item.algorithm,
                        "family": item.family,
                        "strength": item.strength,
                        "sources": list(item.sources),
                        "evidence": list(item.evidence),
                    }
                    for item in report.algorithms
                ],
                "families": _family_counts(report),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format algorithm facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 算法识别 ===",
            f"证据: 常量 {data.get('constant_count', 0):,} /"
            f" 符号 {data.get('symbol_count', 0):,} /"
            f" 字符串 {data.get('string_count', 0):,}",
            f"判定: {data.get('algorithm_count', 0)} 项"
            f"（多源印证 {data.get('corroborated_count', 0)} 项）",
        ]
        if data.get("scan_truncated"):
            lines.append("注意: 输入已按上限截断，尾部未扫描")
        algorithms = data.get("algorithms", [])
        if algorithms:
            lines.append("")
            lines.append("判定（按名称）:")
            for item in algorithms:
                family = _FAMILY_LABELS.get(item["family"], item["family"])
                strength = _STRENGTH_LABELS.get(item["strength"], item["strength"])
                lines.append(
                    f"  {item['algorithm']:<18} [{family}] {strength}"
                    f"  来源 {', '.join(item['sources'])}"
                )
                for detail in item["evidence"][:3]:
                    lines.append(f"      - {detail}")
        else:
            lines.append("未识别出已知算法")
        return "\n".join(lines)


def _family_counts(report) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in report.algorithms:
        counts[item.family] = counts.get(item.family, 0) + 1
    return counts


def _symbol_names(elf, limit: int) -> tuple[str, ...]:
    """Names of the image's defined and imported symbols."""
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
    """Read at most ``limit`` bytes, reporting whether the file was longer."""
    with open(path, "rb") as stream:
        blob = stream.read(limit)
    try:
        size = path.stat().st_size
    except OSError:
        size = len(blob)
    return blob, size > len(blob)


def _optional_elf(path):
    """Parse the ELF header when the target is one; ``None`` otherwise."""
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
