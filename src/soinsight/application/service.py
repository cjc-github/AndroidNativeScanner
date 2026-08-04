"""Application facade used by CLI and future frontends."""

from ..core.models import Diagnostic, DiagnosticLevel
from ..core.runtime import AnalysisRuntime, PlanningError
from ..infrastructure.config import RuntimeConfig
from .requests import AnalysisRequest
from .responses import ApplicationResponse
from .target_resolver import TargetResolutionError, TargetResolver


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
    ) -> ApplicationResponse:
        try:
            target = self.target_resolver.resolve(request.target)
            result = self.runtime.execute(
                target=target,
                analyzer_ids=request.analyzer_ids,
                config=config,
                profile=request.profile,
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
            return ApplicationResponse(result=result)
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
