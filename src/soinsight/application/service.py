"""Application facade used by CLI and future frontends."""

from ..core.analyzer import CancellationToken
from ..core.models import AnalysisStatus, Diagnostic, DiagnosticLevel
from ..core.runtime import AnalysisRuntime, PlanningError, ProgressObserver
from ..infrastructure.config import RuntimeConfig
from .baseline import (
    BaselineError,
    apply_baseline,
    gate_failure,
    load_baseline,
    parse_threshold,
    save_baseline,
)
from .requests import AnalysisRequest, BatchRequest
from .responses import ApplicationResponse, BatchResponse
from .target_resolver import TargetResolutionError, TargetResolver


#: Exit code when the CI gate rejects the result.
GATE_FAILED_EXIT_CODE = 6


def _exit_code_for_status(status: AnalysisStatus) -> int:
    if status is AnalysisStatus.FAILED:
        return 4
    if status is AnalysisStatus.PARTIAL:
        return 5
    return 0


class AnalysisService:
    def __init__(
        self,
        runtime: AnalysisRuntime,
        target_resolver: TargetResolver | None = None,
    ) -> None:
        self.runtime = runtime
        self.target_resolver = target_resolver or TargetResolver()

    def execute(
        self,
        request: AnalysisRequest,
        config: RuntimeConfig,
        observer: ProgressObserver | None = None,
        cancellation: CancellationToken | None = None,
    ) -> ApplicationResponse:
        try:
            target = self.target_resolver.resolve(request.target)
            result = self.runtime.execute(
                target=target,
                analyzer_ids=request.analyzer_ids,
                config=config,
                profile=request.profile,
                observer=observer,
                cancellation=cancellation,
            )
            if not request.analyzer_ids:
                warning = Diagnostic(
                    code="NO_ANALYZERS_SELECTED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "No analyzers are registered or selected; "
                        "the framework completed without analysis work."
                    ),
                )
                result.diagnostics.append(warning)
            exit_code = _exit_code_for_status(result.status)
            exit_code = self._apply_baseline_and_gate(request, result, exit_code)
            return ApplicationResponse(result=result, exit_code=exit_code)
        except TargetResolutionError as exc:
            return ApplicationResponse(
                result=None,
                diagnostics=[
                    Diagnostic(
                        code="INVALID_TARGET",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                    )
                ],
                exit_code=2,
            )
        except PlanningError as exc:
            return ApplicationResponse(
                result=None,
                diagnostics=[
                    Diagnostic(
                        code="ANALYSIS_PLAN_ERROR",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                    )
                ],
                exit_code=3,
            )

    def _apply_baseline_and_gate(
        self, request: AnalysisRequest, result, exit_code: int
    ) -> int:
        """Suppress baselined findings, then turn the result into a gate decision."""
        error = self._apply_baseline(request, result)
        if error is not None:
            return error
        self._update_baseline(request, result)
        return self._apply_gate(request, result, exit_code)

    def _apply_baseline(self, request, result) -> int | None:
        """Mark baselined findings as suppressed; ``None`` when it worked."""
        if request.baseline is None:
            return None
        try:
            baseline = load_baseline(request.baseline)
        except BaselineError as exc:
            result.diagnostics.append(
                Diagnostic(
                    code="BASELINE_UNREADABLE",
                    level=DiagnosticLevel.ERROR,
                    message=str(exc),
                )
            )
            return 2
        result.findings = apply_baseline(result.findings, baseline)
        suppressed = sum(1 for finding in result.findings if finding.suppressed)
        result.diagnostics.append(
            Diagnostic(
                code="BASELINE_APPLIED",
                level=DiagnosticLevel.INFO,
                message=(
                    f"{suppressed} of {len(result.findings)} finding(s) are in "
                    f"the baseline '{request.baseline}'."
                ),
            )
        )
        return None

    def _update_baseline(self, request, result) -> None:
        """Write the accepted findings as the new baseline."""
        if request.update_baseline is None:
            return
        accepted = [finding for finding in result.findings if not finding.suppressed]
        save_baseline(request.update_baseline, accepted)
        result.diagnostics.append(
            Diagnostic(
                code="BASELINE_WRITTEN",
                level=DiagnosticLevel.INFO,
                message=(
                    f"Wrote {len(accepted)} finding fingerprint(s) to "
                    f"'{request.update_baseline}'."
                ),
            )
        )

    def _apply_gate(self, request, result, exit_code: int) -> int:
        """Turn the findings into a CI gate decision."""
        if not request.fail_on:
            return exit_code
        try:
            threshold = parse_threshold(request.fail_on)
        except BaselineError as exc:
            result.diagnostics.append(
                Diagnostic(
                    code="GATE_THRESHOLD_INVALID",
                    level=DiagnosticLevel.ERROR,
                    message=str(exc),
                )
            )
            return 2
        failure = gate_failure(result.findings, threshold)
        if failure is None:
            result.diagnostics.append(
                Diagnostic(
                    code="GATE_PASSED",
                    level=DiagnosticLevel.INFO,
                    message=(
                        f"No unsuppressed finding reaches "
                        f"'{threshold.value}'; the gate passes."
                    ),
                )
            )
        else:
            result.diagnostics.append(
                Diagnostic(
                    code="GATE_FAILED",
                    level=DiagnosticLevel.ERROR,
                    message=(
                        f"'{failure.title}' is {failure.severity.value}, at or "
                        f"above the '{threshold.value}' gate threshold."
                    ),
                )
            )
            return GATE_FAILED_EXIT_CODE
        return exit_code

    def execute_batch(
        self,
        request: BatchRequest,
        config: RuntimeConfig,
        observer: ProgressObserver | None = None,
        cancellation: CancellationToken | None = None,
    ) -> BatchResponse:
        """Analyze every selected target and collect the outcomes.

        A target that fails does not stop the batch: its failure is recorded
        and the remaining targets still run. The batch exit code is the worst
        outcome of the run, so a CI gate on a directory fails the whole step
        when any member fails.
        """
        try:
            targets = self.target_resolver.resolve_many(
                request.targets,
                include=request.include,
                exclude=request.exclude,
            )
        except TargetResolutionError as exc:
            return BatchResponse(
                results={},
                failed=[],
                exit_code=2,
                diagnostics=[
                    Diagnostic(
                        code="INVALID_TARGET",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                    )
                ],
            )

        results: dict[str, object] = {}
        failed: list[str] = []
        diagnostics: list[Diagnostic] = []
        exit_code = 0
        accepted: list = []

        for target in targets:
            try:
                result = self.runtime.execute(
                    target=target,
                    analyzer_ids=request.analyzer_ids,
                    config=config,
                    profile=request.profile,
                    observer=observer,
                    cancellation=cancellation,
                )
            except PlanningError as exc:
                failed.append(str(target.path))
                diagnostics.append(
                    Diagnostic(
                        code="ANALYSIS_PLAN_ERROR",
                        level=DiagnosticLevel.ERROR,
                        message=f"{target.path}: {exc}",
                    )
                )
                exit_code = max(exit_code, 3)
                continue

            target_exit = _exit_code_for_status(result.status)
            error = self._apply_baseline(request, result)
            if error is not None:
                target_exit = error
            else:
                target_exit = self._apply_gate(request, result, target_exit)
            if request.update_baseline is not None:
                accepted.extend(
                    finding for finding in result.findings if not finding.suppressed
                )

            results[str(target.real_path)] = result
            if target_exit != 0:
                failed.append(str(target.path))
                exit_code = max(exit_code, target_exit)

        if request.update_baseline is not None:
            save_baseline(request.update_baseline, accepted)
            diagnostics.append(
                Diagnostic(
                    code="BASELINE_WRITTEN",
                    level=DiagnosticLevel.INFO,
                    message=(
                        f"Wrote {len(accepted)} finding fingerprint(s) to "
                        f"'{request.update_baseline}' across {len(targets)} target(s)."
                    ),
                )
            )

        return BatchResponse(
            results=results,
            failed=failed,
            diagnostics=diagnostics,
            exit_code=exit_code,
            target_count=len(targets),
        )
