"""``automation.fuzz-target``: rank static entry points a fuzzer could drive."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.fuzz_targets import rank_candidates

ANALYZER_ID = "automation.fuzz-target"

_DEFAULT_OPTIONS = {
    "max_targets": 50,
    "min_score": 0,
}

_KIND_LABELS = {"jni": "JNI 导出", "parser": "解析类导出", "export": "普通导出"}


class AutomationFuzzTargetAnalyzer(Analyzer):
    """Rank exported functions and JNI methods as fuzz candidates."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Fuzz Target Analyzer",
        version="1.0.0",
        description="Rank static entry points a fuzzer could drive.",
        requires=("basic.symbols", "basic.types"),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []
        symbols = context.require("basic.symbols")
        types = context.require("basic.types")

        exported = tuple(symbols.data.get("functions") or ())
        signatures = tuple(types.data.get("signatures") or ())
        report = rank_candidates(
            exported,
            signatures,
            max_targets=options["max_targets"],
            min_score=options["min_score"],
        )
        if not report.candidates:
            diagnostics.append(
                Diagnostic(
                    code="FUZZ_NO_ENTRYPOINTS",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "No exported function passed the filters; a stripped or "
                        "symbol-less image gives a fuzzer nothing to drive."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "exported_functions": len(exported),
                "signature_count": len(signatures),
                "target_count": len(report.candidates),
                "jni_count": report.jni_count,
                "parser_like_count": report.parser_like_count,
                "buffer_length_pair_count": report.buffer_length_pair_count,
                "max_targets": options["max_targets"],
                "min_score": options["min_score"],
                "heuristic": True,
                "targets": [item.as_dict() for item in report.candidates],
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format fuzz-target candidates as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== Fuzz 目标识别 ===",
            f"导出函数: {data.get('exported_functions', 0)}"
            f"（签名 {data.get('signature_count', 0)} 个可用）",
            f"候选: {data.get('target_count', 0)} 个"
            f"（JNI {data.get('jni_count', 0)} / 解析类 {data.get('parser_like_count', 0)}）",
            f"可直接喂入数据: {data.get('buffer_length_pair_count', 0)} 个",
            "说明: 评分是启发式排序，不等于可 fuzz 性结论",
        ]
        targets = data.get("targets", [])
        if targets:
            lines.append("")
            lines.append("候选（按评分）:")
            for item in targets[:_TEXT_LIMIT]:
                kind = _KIND_LABELS.get(item["kind"], item["kind"])
                lines.append(
                    f"  {item['score']:>3}  {item['name']}  [{kind}]"
                )
                if item["parameters"]:
                    shapes = ", ".join(
                        f"{parameter['type'] or '?'} {parameter['name']}".strip()
                        for parameter in item["parameters"]
                    )
                    lines.append(f"       参数: {shapes}")
                for reason in item["reasons"]:
                    lines.append(f"       - {reason}")
            remaining = len(targets) - _TEXT_LIMIT
            if remaining > 0:
                lines.append(f"  ... 以及另外 {remaining} 个")
        else:
            lines.append("未识别出可驱动的入口")
        return "\n".join(lines)


_TEXT_LIMIT = 8


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_targets", "min_score"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(0, value)
    resolved["max_targets"] = max(1, resolved["max_targets"])
    return resolved
