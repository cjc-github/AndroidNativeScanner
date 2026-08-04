"""Aggregate analyzer results into a scan result."""

from ..analyzer import AnalysisContext
from ..models import AnalysisStatus, ScanResult
from ...version import __version__
from .plan import AnalysisPlan


class ResultAggregator:
    def aggregate(
        self,
        context: AnalysisContext,
        plan: AnalysisPlan,
        duration_ms: int,
        profile: str | None = None,
    ) -> ScanResult:
        results = context.results
        statuses = {result.status for result in results.values()}

        if not results:
            status = AnalysisStatus.SUCCESS
        elif statuses <= {AnalysisStatus.SUCCESS, AnalysisStatus.CACHED}:
            status = AnalysisStatus.SUCCESS
        elif statuses <= {
            AnalysisStatus.FAILED,
            AnalysisStatus.SKIPPED,
            AnalysisStatus.TIMEOUT,
            AnalysisStatus.CANCELLED,
        }:
            status = AnalysisStatus.FAILED
        else:
            status = AnalysisStatus.PARTIAL

        findings = list(context.findings)
        findings.extend(
            finding
            for analyzer_id in plan.resolved
            if analyzer_id in results
            for finding in results[analyzer_id].findings
        )

        diagnostics = list(context.diagnostics)
        for result in results.values():
            diagnostics.extend(result.diagnostics)

        return ScanResult(
            target=context.target,
            status=status,
            results=results,
            findings=findings,
            diagnostics=diagnostics,
            requested_analyzers=plan.requested,
            resolved_analyzers=plan.resolved,
            profile=profile,
            duration_ms=duration_ms,
            tool_version=__version__,
        )
