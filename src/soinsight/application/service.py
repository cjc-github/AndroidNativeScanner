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
from .requests import AnalysisRequest
from .responses import ApplicationResponse
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
        if request.baseline is not None:
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

        if request.update_baseline is not None:
            accepted = [
                finding for finding in result.findings if not finding.suppressed
            ]
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

        if request.fail_on:
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
