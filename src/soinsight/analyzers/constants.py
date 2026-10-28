"""``advanced.constants``: scan for well-known algorithm constant tables."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.constants import SIGNATURES, scan
from ..infrastructure.elf import ElfFormatError, parse_elf

ANALYZER_ID = "advanced.constants"

_DEFAULT_OPTIONS = {
    "max_scan_bytes": 33554432,
    "max_hits_per_algorithm": 8,
}

_FAMILY_LABELS = {
    "cipher": "加密",
    "hash": "哈希",
    "compression": "压缩",
    "encoding": "编码",
    "checksum": "校验",
}


class AdvancedConstantsAnalyzer(Analyzer):
    """Locate the constant tables that identify cryptographic primitives."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Constants Analyzer",
        version="1.0.0",
        description="Scan for well-known algorithm constant tables.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="CONSTANTS_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        elf = _optional_elf(target.real_path)
        hits = scan(
            blob,
            max_hits_per_algorithm=options["max_hits_per_algorithm"],
        )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "scanned_bytes": len(blob),
                "file_size": target.size,
                "scan_truncated": truncated,
                "signature_count": len(SIGNATURES),
                "hit_count": len(hits),
                "hits": [
                    {
                        "algorithm": hit.algorithm,
                        "family": hit.family,
                        "offsets": [hex(offset) for offset in hit.offsets],
                        "sections": [
                            _section_of(elf, offset) for offset in hit.offsets
                        ],
                    }
                    for hit in hits
                ],
                "families": _family_counts(hits),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format constant-table facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 特征常量 ===",
            f"扫描字节: {data.get('scanned_bytes', 0):,}"
            f"（文件 {data.get('file_size', 0):,}）",
            f"特征表: {data.get('signature_count', 0)} 张",
            f"命中: {data.get('hit_count', 0)} 项",
        ]
        if data.get("scan_truncated"):
            lines.append("注意: 输入已按上限截断，尾部未扫描")
        hits = data.get("hits", [])
        if hits:
            lines.append("")
            lines.append("命中（按算法）:")
            for hit in hits:
                label = _FAMILY_LABELS.get(hit["family"], hit["family"])
                sections = {
                    section for section in hit["sections"] if section is not None
                }
                where = ", ".join(sorted(sections)) if sections else "未知分节"
                lines.append(
                    f"  {hit['algorithm']:<20} [{label}] "
                    f"{len(hit['offsets'])} 处  {where}"
                )
        else:
            lines.append("未发现已知算法常量表")
        return "\n".join(lines)


def _family_counts(hits) -> dict[str, int]:
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.family] = counts.get(hit.family, 0) + 1
    return counts


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


def _section_of(elf, offset: int) -> Optional[str]:
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


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_scan_bytes", "max_hits_per_algorithm"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    return resolved
