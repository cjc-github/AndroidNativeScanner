"""Rule evaluation engine."""

from ..analyzer import AnalysisContext
from ..models import AnalysisStatus, Diagnostic, DiagnosticLevel
from .registry import RuleRegistry


class RuleEngine:
    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry()

    def evaluate(self, context: AnalysisContext) -> None:
        for rule in self.registry.enabled_rules():
            missing = [
                analyzer_id
                for analyzer_id in rule.metadata.requires
                if context.optional(analyzer_id) is None
                or context.optional(analyzer_id).status
                not in {AnalysisStatus.SUCCESS, AnalysisStatus.CACHED}
            ]
            if missing:
                context.diagnostics.append(
                    Diagnostic(
                        code="RULE_DEPENDENCY_MISSING",
                        level=DiagnosticLevel.WARNING,
                        message=(
                            f"Rule '{rule.metadata.id}' skipped; unavailable results: "
                            + ", ".join(missing)
                        ),
                    )
                )
                continue
            try:
                context.add_findings(rule.evaluate(context))
            except Exception as exc:  # Rules are third-party extension boundaries.
                context.diagnostics.append(
                    Diagnostic(
                        code="RULE_EXCEPTION",
                        level=DiagnosticLevel.ERROR,
                        message=f"Rule '{rule.metadata.id}' failed: {exc}",
                        details={"exception_type": type(exc).__name__},
                    )
                )
