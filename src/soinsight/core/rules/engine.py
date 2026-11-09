"""Rule evaluation engine."""

from ..analyzer import AnalysisContext
from ..models import AnalysisStatus, Diagnostic, DiagnosticLevel, Finding
from .registry import RuleRegistry


class RuleEngine:
    """Evaluate rules whose required analyzer results are available.

    A rule is a judgment over data that may legitimately be absent, so a
    missing dependency is a silent skip rather than a scan diagnostic: basic
    scans keep their output clean, and ``RULE_EXCEPTION`` still reports a
    broken rule implementation.
    """

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry()

    def evaluate(self, context: AnalysisContext) -> None:
        """Evaluate the rules whose dependencies are available.

        The engine may be called more than once for the same run -- the
        scheduler evaluates it between the stages so that a summarizing
        analyzer sees the findings -- so the findings it produces are
        deduplicated by fingerprint. Without that, a rule that fires on the
        same facts would be reported once per evaluation.
        """
        for rule in self.registry.enabled_rules():
            missing = [
                analyzer_id
                for analyzer_id in rule.metadata.requires
                if context.optional(analyzer_id) is None
                or context.optional(analyzer_id).status
                not in {AnalysisStatus.SUCCESS, AnalysisStatus.CACHED}
            ]
            if missing:
                continue
            try:
                produced = rule.evaluate(context)
            except Exception as exc:  # Rules are third-party extension boundaries.
                context.diagnostics.append(
                    Diagnostic(
                        code="RULE_EXCEPTION",
                        level=DiagnosticLevel.ERROR,
                        message=f"Rule '{rule.metadata.id}' failed: {exc}",
                        details={"exception_type": type(exc).__name__},
                    )
                )
                continue
            context.add_findings(self._deduplicate(context, produced))

    def _deduplicate(
        self, context: AnalysisContext, produced: list[Finding]
    ) -> list[Finding]:
        """Drop the findings that are already on the context.

        A finding without a fingerprint cannot be compared, so it is kept:
        dropping it would lose a finding the rule meant to report.
        """
        if not produced:
            return []
        known = {
            finding.fingerprint
            for finding in context.findings
            if finding.fingerprint
        }
        if not known:
            return produced
        fresh: list[Finding] = []
        seen: set[str] = set()
        for finding in produced:
            fingerprint = finding.fingerprint
            if not fingerprint:
                fresh.append(finding)
                continue
            if fingerprint in known or fingerprint in seen:
                continue
            seen.add(fingerprint)
            fresh.append(finding)
        return fresh
