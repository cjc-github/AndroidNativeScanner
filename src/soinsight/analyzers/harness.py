"""``automation.harness``: generate a fuzz harness skeleton for one entry point."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.harness import build_harness

ANALYZER_ID = "automation.harness"

_DEFAULT_OPTIONS = {
    "target_name": "",
    "engine": "libfuzzer",
}


class AutomationHarnessAnalyzer(Analyzer):
    """Generate a harness template from the ranked fuzz targets."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Harness Analyzer",
        version="1.0.0",
        description="Generate a fuzz harness skeleton for a chosen entry point.",
        requires=("automation.fuzz-target",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []
        fuzz = context.require("automation.fuzz-target")
        candidates = list(fuzz.data.get("targets") or ())

        chosen = _select(candidates, options["target_name"])
        if chosen is None:
            message = (
                f"未找到入口 '{options['target_name']}'"
                if options["target_name"]
                else "没有可生成 harness 的候选入口"
            )
            diagnostics.append(
                Diagnostic(
                    code="HARNESS_NO_TARGET",
                    level=DiagnosticLevel.WARNING,
                    message=message,
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.SUCCESS,
                data={
                    "generated": False,
                    "reason": message,
                    "engine": options["engine"],
                    "target_name": options["target_name"],
                    "harness": None,
                },
                diagnostics=diagnostics,
            )

        try:
            draft = build_harness(chosen, engine=options["engine"])
        except ValueError as exc:
            diagnostics.append(
                Diagnostic(
                    code="HARNESS_UNSUPPORTED_ENGINE",
                    level=DiagnosticLevel.ERROR,
                    message=str(exc),
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.SUCCESS,
                data={
                    "generated": False,
                    "reason": str(exc),
                    "engine": options["engine"],
                    "target_name": options["target_name"],
                    "harness": None,
                },
                diagnostics=diagnostics,
            )

        if draft.warnings:
            diagnostics.append(
                Diagnostic(
                    code="HARNESS_TEMPLATE_INCOMPLETE",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"{len(draft.warnings)} 处参数无法自动满足，生成的是模板，"
                        "需要人工补全后再编译运行。"
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "generated": True,
                "reason": "template generated; nothing was executed",
                "engine": draft.engine,
                "target_name": draft.target,
                "candidate_score": chosen.get("score", 0),
                "harness": draft.as_dict(),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the generated harness as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = ["=== Harness 生成 ==="]
        if not data.get("generated"):
            lines.append(f"未生成: {data.get('reason')}")
            return "\n".join(lines)
        harness = data.get("harness") or {}
        lines.append(f"目标: {harness.get('target')}（{harness.get('engine')}）")
        lines.append(f"评分: {data.get('candidate_score')}")
        lines.append("说明: 模板，未执行目标；编译与运行由人工完成")
        warnings = harness.get("warnings") or ()
        if warnings:
            lines.append(f"待人工处理: {len(warnings)} 处")
            for warning in warnings:
                lines.append(f"  - {warning}")
        lines.append("")
        lines.append("--- harness.c ---")
        lines.extend(str(harness.get("source") or "").rstrip("\n").splitlines())
        return "\n".join(lines)


def _select(candidates: list[dict], target_name: str) -> dict | None:
    """Pick the requested entry point, or the highest-scoring candidate."""
    if target_name:
        for candidate in candidates:
            if target_name in (
                str(candidate.get("name") or ""),
                str(candidate.get("linkage_name") or ""),
            ):
                return candidate
        return None
    return candidates[0] if candidates else None


def _resolve_options(context) -> dict:
    """Read capability options with defaults and types enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    name = declared.get("target_name")
    if isinstance(name, str) and name.strip():
        resolved["target_name"] = name.strip()
    engine = declared.get("engine")
    if isinstance(engine, str) and engine.strip():
        resolved["engine"] = engine.strip().lower()
    return resolved
