"""``dynamic.trace``: plan a sandboxed trace run when execution is authorized.

The capability is wired into the scheduler so the gate and the isolation
requirements are enforced by real code rather than by documentation, but it does
not start a process on its own: it reports the refusal when execution is not
authorized, the missing isolation primitive when no sandbox is installed, and
the exact command line it would run when both are in place. Collecting the
event stream is a separate step that needs a harness for a shared object.
"""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.execution import (
    DryRunExecutor,
    ExecutionRequest,
    authorize,
    detect_sandbox,
)

ANALYZER_ID = "dynamic.trace"

_DEFAULT_OPTIONS = {
    "timeout_seconds": 10,
    "memory_mib": 512,
}


class DynamicTraceAnalyzer(Analyzer):
    """Plan a sandboxed runtime trace, or explain why it will not run."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Runtime Trace",
        version="1.0.0",
        description="Plan a sandboxed runtime trace under an explicit authorization.",
        requires=("basic.file",),
        # The outcome depends on the authorization config and on which
        # sandbox is installed, neither of which is in the cache key.
        cacheable=False,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []
        authorization = authorize(context.config, target.real_path)

        if not authorization.granted:
            diagnostics.append(
                Diagnostic(
                    code="DYNAMIC_EXECUTION_NOT_AUTHORIZED",
                    level=DiagnosticLevel.WARNING,
                    message=authorization.reason,
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.SUCCESS,
                data={
                    "executed": False,
                    "state": "not-authorized",
                    "reason": authorization.reason,
                    "authorization": {
                        "granted": False,
                        "allow_listed": authorization.allow_listed,
                    },
                    "events": [],
                },
                diagnostics=diagnostics,
            )

        sandbox = detect_sandbox()
        if sandbox is None:
            reason = (
                "未检测到可用的隔离原语（bwrap / firejail / docker / unshare），"
                "拒绝在宿主上直接执行不可信代码。"
            )
            diagnostics.append(
                Diagnostic(
                    code="DYNAMIC_SANDBOX_UNAVAILABLE",
                    level=DiagnosticLevel.WARNING,
                    message=reason,
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.SUCCESS,
                data={
                    "executed": False,
                    "state": "no-sandbox",
                    "reason": reason,
                    "authorization": {"granted": True, "allow_listed": True},
                    "events": [],
                },
                diagnostics=diagnostics,
            )

        request = ExecutionRequest(
            target=target.real_path,
            argv=(str(target.real_path),),
            timeout_seconds=options["timeout_seconds"],
            memory_mib=options["memory_mib"],
        )
        plan = DryRunExecutor(sandbox).plan(request)
        diagnostics.append(
            Diagnostic(
                code="DYNAMIC_DRY_RUN",
                level=DiagnosticLevel.INFO,
                message=(
                    "已生成沙箱执行计划，但未启动任何进程：采集器尚未接入，"
                    "共享库还需要外部 harness 才能运行。"
                ),
                analyzer_id=ANALYZER_ID,
            )
        )
        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "executed": False,
                "state": "planned",
                "reason": "authorized and sandboxed; the plan is ready, no process started",
                "authorization": {"granted": True, "allow_listed": True},
                "sandbox": sandbox.name,
                "plan": plan.as_dict(),
                "events": [],
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the dynamic-trace state as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        state = data.get("state")
        lines = ["=== 运行时 Trace ==="]
        if state == "planned":
            lines.append(f"沙箱: {data.get('sandbox')}")
            plan = data.get("plan") or {}
            lines.append("执行计划（未启动）:")
            lines.append("  " + " ".join(plan.get("argv", [])))
            lines.append(
                f"  超时 {plan.get('timeout_seconds')}s /"
                f" 内存上限 {plan.get('memory_mib')} MiB"
            )
        else:
            lines.append("状态: 未执行")
            lines.append(f"原因: {data.get('reason')}")
        return "\n".join(lines)


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("timeout_seconds", "memory_mib"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    return resolved
