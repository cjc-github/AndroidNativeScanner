"""Analyzer execution scheduler.

Serial by default; when `jobs > 1`, analyzers within an independent stage run
concurrently in a thread pool. The stage model preserves the boundary required
for parallel execution without changing analyzer APIs.

Each analyzer runs under a watchdog so that a hanging analyzer cannot hang the
run: on timeout the result is marked ``TIMEOUT`` and the abandoned thread is
left to finish on its own. Python cannot kill a thread, so the analyzer may
still write to the shared context afterwards; the scheduler remains the only
writer of results, and a timed-out analyzer's findings are best-effort.
"""

from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from time import perf_counter

from ..analyzer import AnalysisContext, AnalyzerRegistry
from ..models import (
    AnalysisResult,
    AnalysisStatus,
    Diagnostic,
    DiagnosticLevel,
)
from .plan import AnalysisPlan
from .progress import (
    KIND_ANALYZER_FINISH,
    KIND_ANALYZER_START,
    KIND_STAGE_START,
    ProgressEvent,
    ProgressObserver,
    emit,
)

_DEFAULT_TIMEOUT_SECONDS = 60


class AnalyzerTimeoutError(Exception):
    """Raised internally when an analyzer exceeds its time budget."""


class DAGScheduler:
    def run(
        self,
        plan: AnalysisPlan,
        registry: AnalyzerRegistry,
        context: AnalysisContext,
        jobs: int = 1,
        observer: ProgressObserver | None = None,
        timeout_seconds: int | None = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        total = len(plan.resolved)
        for stage_index, stage in enumerate(plan.stages):
            pending = [
                analyzer_id
                for analyzer_id in stage.analyzer_ids
                if analyzer_id not in context.results
            ]
            if not pending:
                continue
            emit(
                observer,
                ProgressEvent(
                    kind=KIND_STAGE_START,
                    stage_index=stage_index,
                    stage_size=len(pending),
                    total_analyzers=total,
                    completed_analyzers=len(context.results),
                ),
            )
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
                    self._run_one(
                        analyzer_id,
                        registry,
                        context,
                        observer,
                        timeout_seconds,
                        total,
                    )
            else:
                with ThreadPoolExecutor(max_workers=jobs) as executor:
                    list(
                        executor.map(
                            lambda analyzer_id: self._run_one(
                                analyzer_id,
                                registry,
                                context,
                                observer,
                                timeout_seconds,
                                total,
                            ),
                            pending,
                        )
                    )

    def _run_one(
        self,
        analyzer_id: str,
        registry: AnalyzerRegistry,
        context: AnalysisContext,
        observer: ProgressObserver | None = None,
        timeout_seconds: int | None = _DEFAULT_TIMEOUT_SECONDS,
        total_analyzers: int = 0,
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

        budget = _effective_timeout(metadata, timeout_seconds)
        emit(
            observer,
            ProgressEvent(
                kind=KIND_ANALYZER_START,
                analyzer_id=analyzer_id,
                total_analyzers=total_analyzers,
                completed_analyzers=len(context.results),
            ),
        )
        started = perf_counter()
        try:
            result = _invoke(analyzer, context, budget)
            if result.analyzer_id != analyzer_id:
                raise ValueError(
                    f"Analyzer returned id '{result.analyzer_id}', expected '{analyzer_id}'"
                )
            if not result.analyzer_version:
                result.analyzer_version = metadata.version
        except AnalyzerTimeoutError:
            result = AnalysisResult(
                analyzer_id=analyzer_id,
                analyzer_version=metadata.version,
                status=AnalysisStatus.TIMEOUT,
                diagnostics=[
                    Diagnostic(
                        code="ANALYZER_TIMEOUT",
                        level=DiagnosticLevel.ERROR,
                        message=(
                            f"Analyzer '{analyzer_id}' exceeded its "
                            f"{budget} second budget and was abandoned."
                        ),
                        analyzer_id=analyzer_id,
                        details={"timeout_seconds": budget},
                    )
                ],
            )
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
        emit(
            observer,
            ProgressEvent(
                kind=KIND_ANALYZER_FINISH,
                analyzer_id=analyzer_id,
                total_analyzers=total_analyzers,
                completed_analyzers=len(context.results),
                status=result.status.value,
                duration_ms=result.duration_ms,
            ),
        )


def _effective_timeout(metadata, configured: int | None) -> int:
    """Pick the tighter of the run-level and per-analyzer budgets."""
    candidates = [
        value
        for value in (configured, getattr(metadata, "timeout_seconds", None))
        if isinstance(value, int) and value > 0
    ]
    return min(candidates) if candidates else _DEFAULT_TIMEOUT_SECONDS


def _invoke(analyzer, context, budget: int):
    """Run ``analyzer`` under a watchdog, raising ``AnalyzerTimeoutError``.

    A daemon thread is used rather than a pool: an abandoned pool worker would
    keep the interpreter alive at exit, which would defeat Ctrl+C.
    """
    if budget <= 0:
        return analyzer.analyze(context.target, context)

    outcome: dict[str, object] = {}

    def runner() -> None:
        try:
            outcome["result"] = analyzer.analyze(context.target, context)
        except BaseException as exc:  # noqa: BLE001 - forwarded to the caller.
            outcome["error"] = exc

    worker = Thread(target=runner, daemon=True, name=f"soinsight-{analyzer.metadata.id}")
    worker.start()
    worker.join(budget)
    if worker.is_alive():
        raise AnalyzerTimeoutError(analyzer.metadata.id)
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome["result"]  # type: ignore[return-value]
