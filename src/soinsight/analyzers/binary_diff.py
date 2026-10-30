"""``automation.binary-diff``: diff two ELF images at the symbol level."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.binary_diff import diff_functions
from ..infrastructure.elf import ElfFormatError, parse_elf

ANALYZER_ID = "automation.binary-diff"


class AutomationBinaryDiffAnalyzer(Analyzer):
    """Compare the defined function symbols of the old and new image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Binary Diff",
        version="1.0.0",
        description="Diff the function symbol sets of two ELF images.",
        requires=(),
        # A two-input diff is only meaningful when both paths are configured;
        # a plain single-target scan must never pull it in by default.
        default_enabled=False,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        old_target = _load_target(context, "old")
        new_target = _load_target(context, "new")
        diagnostics: list[Diagnostic] = []
        if old_target is None or new_target is None:
            diagnostics.append(
                Diagnostic(
                    code="DIFF_TARGETS_MISSING",
                    level=DiagnosticLevel.ERROR,
                    message=(
                        "binary-diff 需要两个目标：请提供 old 与 new 两个镜像"
                        "（通过 dynamic_execution.targets 之外的 "
                        "binary_diff.old_path / binary_diff.new_path 配置）。"
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                data={"diffed": False},
                diagnostics=diagnostics,
            )

        old_functions = _function_records(old_target)
        new_functions = _function_records(new_target)
        if old_functions is None or new_functions is None:
            bad = old_target if old_functions is None else new_target
            diagnostics.append(
                Diagnostic(
                    code="DIFF_INVALID_ELF",
                    level=DiagnosticLevel.ERROR,
                    message=f"'{bad}' is not a valid ELF image.",
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                data={"diffed": False},
                diagnostics=diagnostics,
            )

        report = diff_functions(old_functions, new_functions)
        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "diffed": True,
                "old": {
                    "path": str(old_target),
                    "function_count": len(old_functions),
                },
                "new": {
                    "path": str(new_target),
                    "function_count": len(new_functions),
                },
                "change_count": len(report.changes),
                "added_count": len(report.added),
                "removed_count": len(report.removed),
                "moved_count": len(report.moved),
                "resized_count": len(report.resized),
                "changes": [item.as_dict() for item in report.changes],
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the function-level diff as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        if not data.get("diffed"):
            return None
        old = data.get("old") or {}
        new = data.get("new") or {}
        lines = [
            "=== Binary Diff ===",
            f"旧镜像: {old.get('path')}（{old.get('function_count')} 个函数）",
            f"新镜像: {new.get('path')}（{new.get('function_count')} 个函数）",
            f"变化: +{data.get('added_count', 0)} 新增"
            f" / -{data.get('removed_count', 0)} 移除"
            f" / ~{data.get('moved_count', 0)} 移动"
            f" / ≈{data.get('resized_count', 0)} 大小变化",
        ]
        changes = data.get("changes") or []
        if changes:
            lines.append("")
            lines.append("明细:")
            for item in changes[:_TEXT_LIMIT]:
                marker = {
                    "added": "+",
                    "removed": "-",
                    "moved": "~",
                    "resized": "≈",
                }.get(item["change"], " ")
                sizes = ""
                if item.get("old_size") is not None and item.get("new_size") is not None:
                    sizes = f" ({item['old_size']} -> {item['new_size']} B)"
                lines.append(
                    f"  {marker} {item.get('name')}  "
                    f"{item.get('old_address') or ''}"
                    f"{' -> ' if item.get('old_address') else ''}"
                    f"{item.get('new_address') or ''}{sizes}"
                )
            remaining = len(changes) - _TEXT_LIMIT
            if remaining > 0:
                lines.append(f"  ... 以及另外 {remaining} 项")
        else:
            lines.append("函数集无变化")
        return "\n".join(lines)


_TEXT_LIMIT = 20


def _load_target(context, side: str):
    """Resolve the per-side path from the config, when configured."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    settings = extra.get("binary_diff") or {}
    if not isinstance(settings, dict):
        return None
    path = settings.get(f"{side}_path")
    return str(path) if path else None


def _function_records(path: str) -> tuple[dict, ...] | None:
    """Defined function symbols of an image; ``None`` when it is not an ELF."""
    try:
        elf = parse_elf(path)
    except (ElfFormatError, OSError):
        return None
    records = []
    for symbol in elf.symbols:
        if not symbol.is_defined or not symbol.is_function or symbol.value <= 0:
            continue
        records.append(
            {
                "name": symbol.name,
                "kind": "function",
                "language": "c++" if symbol.name.startswith("_Z") else "c",
                "address": hex(symbol.value),
                "size": symbol.size,
            }
        )
    return tuple(records)
