"""``automation.report``: turn one run's results into a report, optionally archived.

The capability is deliberately a *view* over an existing run: it summarizes
what the other analyzers produced, renders it in the formats the framework
already supports and can archive the result. It never re-runs an analyzer and
never invents a finding.

Two boundaries are worth stating plainly:

* The report covers the results of the analyzers that ran **before** it.
  The rule engine is evaluated between the scheduler's stages, so its
  findings are part of the report as well.
* Publishing writes files. It is opt-in (``publish``) and writes only under
  the configured root.
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
from ..infrastructure.report_building import build_document, render_report
from ..infrastructure.storage.artifact_store import FileArtifactStore

ANALYZER_ID = "automation.report"

_DEFAULT_OPTIONS = {
    "formats": ["markdown", "json", "sarif", "html", "text"],
    "primary": "markdown",
    "publish": False,
    "reports_root": "reports",
    "include_data": False,
}

_FORMAT_EXTENSIONS = {
    "text": "txt",
    "json": "json",
    "markdown": "md",
    "html": "html",
    "sarif": "sarif",
}

#: The report is a view over the other analyzers, so it has to run after
#: them. A soft dependency only orders the plan; it never pulls an analyzer
#: in, so a report on its own still works.
_SUMMARIZED = (
    "basic.file",
    "basic.elf",
    "basic.symbols",
    "basic.dwarf",
    "basic.types",
    "basic.cpp",
    "basic.disasm",
    "basic.cfg",
    "basic.callgraph",
    "basic.dataflow",
    "basic.dynamic",
    "basic.xref",
    "basic.jni",
    "advanced.strings",
    "advanced.constants",
    "advanced.algorithm",
    "advanced.protocol",
    "advanced.file-format",
    "advanced.library",
    "advanced.compiler",
    "advanced.obfuscation",
    "security.hardening",
    "security.dangerous-api",
    "security.vulnerability",
    "security.risk",
    "security.dynamic-loading",
    "dynamic.trace",
    "dynamic.arguments",
    "dynamic.memory",
    "dynamic.syscalls",
    "dynamic.coverage",
    "automation.binary-diff",
    "automation.fuzz-target",
    "automation.harness",
    "automation.seed",
)


class AutomationReportAnalyzer(Analyzer):
    """Consolidate the run's results into a multi-format report."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Report Automation Analyzer",
        version="1.0.0",
        description=(
            "Summarize the run's analyzer results into one report and "
            "optionally archive it."
        ),
        kind=AnalyzerKind.TRANSFORMER,
        requires=(),
        optional_requires=_SUMMARIZED,
        default_enabled=True,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        document = build_document(
            target,
            context.results,
            _all_findings(context),
            include_data=options["include_data"],
        )
        report = render_report(
            document,
            options["formats"],
            options["primary"],
            include_data=options["include_data"],
        )

        for name, message in report.errors.items():
            diagnostics.append(
                Diagnostic(
                    code="REPORT_FORMAT_FAILED",
                    level=DiagnosticLevel.WARNING,
                    message=f"报告格式 '{name}' 生成失败：{message}",
                    analyzer_id=ANALYZER_ID,
                )
            )

        artifacts = _publish(report, target, options, diagnostics)

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "target": target.name,
                "analyzer_count": len(context.results),
                "result_count": len(context.results),
                "finding_count": len(_all_findings(context)),
                "formats": list(report.formats),
                "rendered_formats": list(report.rendered_formats),
                "primary_format": report.primary_format,
                "report_text": report.primary_text,
                "report_by_format": dict(report.contents),
                "sections": [item.as_dict() for item in document.sections],
                "format_errors": dict(report.errors),
                "artifacts": artifacts,
                "published": bool(artifacts),
                "generated_at": document.generated_at,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Summarize the report; the full document stays in ``report_text``."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        rendered = data.get("rendered_formats") or []
        primary = data.get("primary_format") or ""
        lines = [
            "=== 报告自动化 ===",
            f"目标: {data.get('target') or '(未命名)'}",
            f"分析器: {data.get('analyzer_count', 0)} 个"
            f"，发现项: {data.get('finding_count', 0)} 条",
            f"格式: {', '.join(rendered) or '无'}",
        ]
        if primary:
            lines.append(f"主格式: {primary}")
        artifacts = data.get("artifacts") or []
        if artifacts:
            lines.append(f"已归档: {len(artifacts)} 个文件")
        else:
            lines.append("已归档: 否（未开启 publish）")
        return "\n".join(lines)


def _publish(report, target, options: dict, diagnostics: list[Diagnostic]) -> list[dict]:
    """Archive the rendered report when publishing is enabled."""
    if not options["publish"]:
        return []
    from pathlib import Path

    root = Path(options["reports_root"]).expanduser()
    store = FileArtifactStore(root)
    namespace = f"report/{target.name or 'target'}"
    artifacts: list[dict] = []
    for name, content in report.contents.items():
        extension = _FORMAT_EXTENSIONS.get(name, "txt")
        key = f"index.{extension}"
        payload = content.encode("utf-8")
        try:
            store.put(namespace, key, payload)
        except OSError as exc:
            diagnostics.append(
                Diagnostic(
                    code="REPORT_PUBLISH_FAILED",
                    level=DiagnosticLevel.WARNING,
                    message=f"报告归档失败（{name}）：{exc}",
                    analyzer_id=ANALYZER_ID,
                )
            )
            continue
        artifacts.append(
            {
                "namespace": namespace,
                "key": key,
                "format": name,
                "bytes": len(payload),
                "path": str(root / namespace.replace("/", "_") / key),
            }
        )
    return artifacts


def _resolve_options(context) -> dict:
    """Read capability options with defaults and types enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)

    formats = declared.get("formats")
    if isinstance(formats, str):
        formats = [formats]
    if isinstance(formats, (list, tuple)):
        cleaned = [str(item).strip().lower() for item in formats if str(item).strip()]
        if cleaned:
            resolved["formats"] = cleaned

    primary = declared.get("primary")
    if isinstance(primary, str) and primary.strip():
        resolved["primary"] = primary.strip().lower()

    publish = declared.get("publish")
    if isinstance(publish, bool):
        resolved["publish"] = publish
    elif isinstance(publish, str):
        resolved["publish"] = publish.strip().lower() in ("1", "true", "yes", "on")

    root = declared.get("reports_root")
    if isinstance(root, str) and root.strip():
        resolved["reports_root"] = root.strip()

    include_data = declared.get("include_data")
    if isinstance(include_data, bool):
        resolved["include_data"] = include_data

    return resolved


def _all_findings(context) -> list:
    """Every finding of the run, from both places findings can live in.

    An analyzer reports its own findings on its result (``result.findings``),
    while the rule engine adds its judgments to the shared context
    (``context.findings``). A report covers the whole run, so it takes both
    and removes the duplicates by fingerprint.
    """
    collected = list(context.findings)
    known = {finding.fingerprint for finding in collected if finding.fingerprint}
    for result in context.results.values():
        for finding in result.findings or ():
            fingerprint = finding.fingerprint
            if fingerprint and fingerprint in known:
                continue
            if fingerprint:
                known.add(fingerprint)
            collected.append(finding)
    return collected
