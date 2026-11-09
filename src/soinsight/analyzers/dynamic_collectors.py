"""Shared base for the ``dynamic.*`` collector analyzers.

Every collector answers the same question first: *may* this host run the
target at all? The gate is the authorization block of the configuration plus
a detected isolation primitive, and it is default-deny. Only when the gate
opens does an analyzer report a sandboxed command line -- and even then it
starts nothing.

On top of that gate each collector adds the static facts that make its
runtime observation meaningful: the entry points to sample, the memory
ranges to watch, the system calls to intercept and the basic blocks that
coverage would be measured against.
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

_LEVELS = {
    "info": DiagnosticLevel.INFO,
    "warning": DiagnosticLevel.WARNING,
    "error": DiagnosticLevel.ERROR,
}


class DynamicCollectorAnalyzer(Analyzer):
    """Base class for the runtime collectors."""

    #: The collector kind; one of ``arguments``, ``memory``, ``syscalls``,
    #: ``coverage``.
    collector_kind = ""

    metadata = AnalyzerMetadata(
        id="dynamic.collector",
        name="Dynamic Collector",
        version="1.0.0",
        description="Plan a sandboxed runtime collection.",
        kind=AnalyzerKind.COLLECTOR,
        requires=(),
        optional_requires=(),
        default_enabled=True,
        # The outcome depends on the authorization config and on which
        # sandbox is installed, neither of which is in the cache key.
        cacheable=False,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context, self.metadata.id)
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
                level=_LEVELS.get(item.get("level", "warning"), DiagnosticLevel.WARNING),
                message=item["message"],
                analyzer_id=self.metadata.id,
            )
            for item in gate.get("diagnostics") or ()
        ]

        entrypoint = options["entrypoint"] or self._default_entrypoint(context)
        try:
            spec = build_driver_plan(
                self.collector_kind,
                target.real_path,
                entrypoint,
                timeout_seconds=options["timeout_seconds"],
                memory_mib=options["memory_mib"],
            )
        except Exception as exc:  # pragma: no cover - 只在种类名写错时发生
            diagnostics.append(
                Diagnostic(
                    code="DYNAMIC_COLLECTOR_UNAVAILABLE",
                    level=DiagnosticLevel.WARNING,
                    message=f"无法构造采集器计划：{exc}",
                    analyzer_id=self.metadata.id,
                )
            )
            spec = None

        facts = self.collect_facts(context)

        harness = ""
        if entrypoint:
            harness = dlopen_harness_source(
                str(target.real_path),
                entrypoint,
                arguments=self.harness_arguments(context),
            )

        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "kind": self.collector_kind,
                "executed": False,
                "state": gate["state"],
                "authorized": gate["authorized"],
                "reason": gate["reason"],
                "sandbox": gate["sandbox"],
                "plan": gate["plan"],
                "entrypoint": entrypoint,
                "spec": spec.as_dict() if spec else None,
                "harness": harness,
                **facts,
            },
            diagnostics=diagnostics,
        )

    def collect_facts(self, context) -> dict:
        """The static facts that make this collector's observation useful."""
        return {}

    def _default_entrypoint(self, context) -> str:
        """The entry point the collector would call, when one is known."""
        return ""

    def harness_arguments(self, context) -> tuple[str, ...]:
        """The C types the harness prototype should use."""
        return ()

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Describe the collector's state and plan."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            f"=== 动态采集: {data.get('kind', '')} ===",
            f"状态: {data.get('state')}",
        ]
        if data.get("state") == "planned":
            plan = data.get("plan") or {}
            lines.append(f"沙箱: {data.get('sandbox')}")
            lines.append("执行计划（未启动）:")
            lines.append("  " + " ".join(plan.get("argv", [])))
            lines.append(
                f"  超时 {plan.get('timeout_seconds')}s /"
                f" 内存上限 {plan.get('memory_mib')} MiB"
            )
            if data.get("entrypoint"):
                lines.append(f"入口: {data['entrypoint']}")
        else:
            lines.append(f"原因: {data.get('reason')}")
        for key, value in self.fact_lines(data):
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    def fact_lines(self, data: dict) -> list[tuple[str, object]]:
        """Extra lines the text renderer shows for this collector."""
        return []


def _resolve_options(context, analyzer_id: str) -> dict:
    """Read capability options with defaults and types enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(analyzer_id, {})
    resolved = {
        "sandbox": "auto",
        "timeout_seconds": 10,
        "memory_mib": 512,
        "entrypoint": "",
    }

    sandbox = declared.get("sandbox")
    if isinstance(sandbox, str) and sandbox.strip():
        resolved["sandbox"] = sandbox.strip().lower()
    entrypoint = declared.get("entrypoint")
    if isinstance(entrypoint, str) and entrypoint.strip():
        resolved["entrypoint"] = entrypoint.strip()
    for key in ("timeout_seconds", "memory_mib"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = resolved[key]
            resolved[key] = max(1, value)
    return resolved
