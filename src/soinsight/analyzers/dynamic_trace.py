"""``dynamic.trace``: plan a sandboxed trace run when execution is authorized.

The capability is wired into the scheduler so the gate and the isolation
requirements are enforced by real code rather than by documentation, but it
does not start a process on its own: it reports the refusal when execution is
not authorized, the missing isolation primitive when no sandbox is installed, and
the exact command line it would run when both are in place.

It shares the substrate with the other collectors -- the authorization gate,
the sandbox detection and the plan/execute separation live in
:mod:`soinsight.infrastructure.dynamic.collector` -- so all five dynamic
capabilities answer the same question in the same way. What is specific to
the trace is what it watches: the library's module loads and its calls, rather
than one kind of observation.

Collecting the event stream is a separate step that needs a harness for a
shared object.
"""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerKind, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.dynamic.collector import (
    build_driver_plan,
    dlopen_harness_source,
    resolve_dynamic_gate,
)

ANALYZER_ID = "dynamic.trace"

_DEFAULT_OPTIONS = {
    "timeout_seconds": 10,
    "memory_mib": 512,
    "sandbox": "auto",
    "entrypoint": "",
}


class DynamicTraceAnalyzer(Analyzer):
    """Plan a sandboxed runtime trace, or explain why it will not run."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Runtime Trace",
        version="1.0.0",
        description="Plan a sandboxed runtime trace under an explicit authorization.",
        kind=AnalyzerKind.COLLECTOR,
        requires=("basic.file",),
        optional_requires=("basic.symbols",),
        # The outcome depends on the authorization config and on which
        # sandbox is installed, neither of which is in the cache key.
        cacheable=False,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        gate = resolve_dynamic_gate(
            context.config,
            target.real_path,
            sandbox=options["sandbox"],
            timeout_seconds=options["timeout_seconds"],
            memory_mib=options["memory_mib"],
        )

        diagnostics = [
            Diagnostic(
                code=item["code"],
                level=(
                    DiagnosticLevel.WARNING
                    if item.get("level") == "warning"
                    else DiagnosticLevel.INFO
                ),
                message=item["message"],
                analyzer_id=ANALYZER_ID,
            )
            for item in gate.get("diagnostics") or ()
        ]

        entrypoint = options["entrypoint"] or _default_entrypoint(context)
        spec = build_driver_plan(
            "trace",
            target.real_path,
            entrypoint,
            timeout_seconds=options["timeout_seconds"],
            memory_mib=options["memory_mib"],
        )

        harness = ""
        if entrypoint:
            harness = dlopen_harness_source(str(target.real_path), entrypoint)

        if gate["state"] == "planned":
            diagnostics.append(
                Diagnostic(
                    code="DYNAMIC_DRY_RUN",
                    level=DiagnosticLevel.INFO,
                    message=(
                        "已生成沙箱执行计划，但未启动任何进程：真实采集器尚未接入，"
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
                "state": gate["state"],
                "reason": gate["reason"],
                "authorized": gate["authorized"],
                "sandbox": gate["sandbox"],
                "plan": gate["plan"],
                "entrypoint": entrypoint,
                "spec": spec.as_dict(),
                "harness": harness,
                # The trace watches the library as a whole, so the events it
                # would collect are named here even though none were.
                "events": [],
                "event_kinds": list(spec.instrumentation),
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
            if data.get("entrypoint"):
                lines.append(f"入口: {data['entrypoint']}")
        else:
            lines.append("状态: 未执行")
            lines.append(f"原因: {data.get('reason')}")
        kinds = data.get("event_kinds") or []
        if kinds:
            lines.append(f"观测点: {', '.join(kinds)}")
        return "\n".join(lines)


def _default_entrypoint(context) -> str:
    """The entry point the trace would drive, when one is known."""
    symbols = context.optional("basic.symbols")
    if symbols is None:
        return ""
    for record in (symbols.data or {}).get("functions") or ():
        name = record.get("name")
        if name:
            return str(name)
    return ""


def _resolve_options(context) -> dict:
    """Read capability options with defaults and types enforced."""
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
    sandbox = declared.get("sandbox")
    if isinstance(sandbox, str) and sandbox.strip():
        resolved["sandbox"] = sandbox.strip().lower()
    entrypoint = declared.get("entrypoint")
    if isinstance(entrypoint, str) and entrypoint.strip():
        resolved["entrypoint"] = entrypoint.strip()
    return resolved
