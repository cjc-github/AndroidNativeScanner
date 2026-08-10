"""Analyzer execution scheduler.

Serial by default; when `jobs > 1`, analyzers within an independent stage run
concurrently in a thread pool. The stage model preserves the boundary required
for parallel execution without changing analyzer APIs.
"""

from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

from ..analyzer import AnalysisContext, AnalyzerRegistry
from ..models import (
    AnalysisResult,
    AnalysisStatus,
    Diagnostic,
    DiagnosticLevel,
)
from .plan import AnalysisPlan


class SerialScheduler:
    def run(
        self,
        plan: AnalysisPlan,
        registry: AnalyzerRegistry,
        context: AnalysisContext,
        jobs: int = 1,
    ) -> None:
        for stage in plan.stages:
            pending = [
                analyzer_id
                for analyzer_id in stage.analyzer_ids
                if analyzer_id not in context.results
            ]
            if not pending:
                continue
            if context.cancellation.cancelled:
                for analyzer_id in pending:
                    context.add_result(
                        AnalysisResult(
                            analyzer_id=analyzer_id,
                            analyzer_version=registry.get(analyzer_id).metadata.version,
                            status=AnalysisStatus.CANCELLED,
                        )
                    )
                continue
            if jobs <= 1 or len(pending) <= 1:
                for analyzer_id in pending:
                    self._run_one(analyzer_id, registry, context)
            else:
                with ThreadPoolExecutor(max_workers=jobs) as executor:
                    list(
                        executor.map(
                            lambda analyzer_id: self._run_one(analyzer_id, registry, context),
                            pending,
                        )
                    )

    def _run_one(
        self,
        analyzer_id: str,
        registry: AnalyzerRegistry,
        context: AnalysisContext,
    ) -> None:
        analyzer = registry.get(analyzer_id)
        metadata = analyzer.metadata

        failed_dependencies = [
            dependency_id
            for dependency_id in metadata.requires
            if context.require(dependency_id).status
            not in {AnalysisStatus.SUCCESS, AnalysisStatus.CACHED}
        ]
        if failed_dependencies:
            context.add_result(
                AnalysisResult(
                    analyzer_id=analyzer_id,
                    analyzer_version=metadata.version,
                    status=AnalysisStatus.SKIPPED,
                    diagnostics=[
                        Diagnostic(
                            code="DEPENDENCY_FAILED",
                            level=DiagnosticLevel.ERROR,
                            message=(
                                "Required analyzer did not complete successfully: "
                                + ", ".join(failed_dependencies)
                            ),
                            analyzer_id=analyzer_id,
                        )
                    ],
                )
            )
            return

        started = perf_counter()
        try:
            result = analyzer.analyze(context.target, context)
            if result.analyzer_id != analyzer_id:
                raise ValueError(
                    f"Analyzer returned id '{result.analyzer_id}', expected '{analyzer_id}'"
                )
            if not result.analyzer_version:
                result.analyzer_version = metadata.version
        except Exception as exc:  # Framework boundary: plugins must not crash the run.
            result = AnalysisResult(
                analyzer_id=analyzer_id,
                analyzer_version=metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[
                    Diagnostic(
                        code="ANALYZER_EXCEPTION",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                        analyzer_id=analyzer_id,
                        details={"exception_type": type(exc).__name__},
                    )
                ],
            )
        result.duration_ms = int((perf_counter() - started) * 1000)
        context.add_result(result)
