"""Consolidate one run's analyzer results into a single report document.

The report is a *view* over facts a run already produced: it never re-runs an
analyzer, never re-computes a finding and never invents one. Every section
names the analyzer it came from, so a reader can tell "this analyzer found
nothing" apart from "this analyzer did not run".

The document is rendered into the formats the framework already speaks
(Text / JSON / Markdown / HTML / SARIF). The raw analyzer payloads are left
out by default because they can run into megabytes; ``include_data`` turns
them back on for machine consumers that want them.

A serializer that raises is recorded as an error for that format only: one
broken format must not cost the whole report.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from ..core.models import AnalysisResult, Finding

__all__ = [
    "ReportDocument",
    "ReportSection",
    "RenderedReport",
    "build_document",
    "render_report",
]

#: How much of an analyzer's own text summary is carried into the report.
_SUMMARY_LIMIT = 400


@dataclass(frozen=True)
class ReportSection:
    """One analyzer's contribution to the report."""

    analyzer_id: str
    status: str
    summary: str
    key_count: int
    finding_count: int
    data: dict = field(default_factory=dict)

    def as_dict(self, include_data: bool = False) -> dict:
        payload = {
            "analyzer_id": self.analyzer_id,
            "status": self.status,
            "summary": self.summary,
            "key_count": self.key_count,
            "finding_count": self.finding_count,
        }
        if include_data:
            payload["data"] = self.data
        return payload


@dataclass(frozen=True)
class ReportDocument:
    """The consolidated report, before it is turned into a format."""

    target: dict
    generated_at: str
    sections: tuple[ReportSection, ...]
    findings: tuple[dict, ...]
    counts: dict

    def as_dict(self, include_data: bool = False) -> dict:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "counts": dict(self.counts),
            "sections": [item.as_dict(include_data) for item in self.sections],
            "findings": [dict(item) for item in self.findings],
        }


@dataclass(frozen=True)
class RenderedReport:
    """The rendered report in every requested format."""

    formats: tuple[str, ...]
    primary_format: str
    contents: dict[str, str]
    errors: dict[str, str]
    document: ReportDocument

    @property
    def primary_text(self) -> str:
        """The primary format's text; empty when that format failed."""
        return self.contents.get(self.primary_format, "")

    @property
    def rendered_formats(self) -> tuple[str, ...]:
        return tuple(name for name in self.formats if name in self.contents)

    def as_dict(self) -> dict:
        return {
            "formats": list(self.formats),
            "rendered_formats": list(self.rendered_formats),
            "primary_format": self.primary_format,
            "format_errors": dict(self.errors),
        }


def _owner_of(finding: Finding, analyzer_ids: Sequence[str]) -> str:
    """Which analyzer a finding belongs to.

    Findings carry the producing analyzer in their rule id (``security.risk``
    rules are named ``security.risk.<case>``), so the longest matching
    analyzer id wins. A finding from a rule engine that no analyzer owns
    keeps an empty owner rather than being attributed to a guess.
    """
    rule_id = getattr(finding, "rule_id", "") or ""
    best = ""
    for analyzer_id in analyzer_ids:
        if rule_id == analyzer_id or rule_id.startswith(analyzer_id + "."):
            if len(analyzer_id) > len(best):
                best = analyzer_id
    return best


def build_document(
    target,
    results: Mapping[str, AnalysisResult],
    findings: Iterable[Finding] = (),
    *,
    include_data: bool = False,
) -> ReportDocument:
    """Summarize every analyzer that took part in the run."""
    analyzer_ids = sorted(results)
    finding_list = list(findings)

    counts: dict[str, int] = {}
    for finding in finding_list:
        owner = _owner_of(finding, analyzer_ids)
        if owner:
            counts[owner] = counts.get(owner, 0) + 1

    sections: list[ReportSection] = []
    for analyzer_id in analyzer_ids:
        result = results[analyzer_id]
        sections.append(
            ReportSection(
                analyzer_id=analyzer_id,
                status=getattr(result.status, "value", str(result.status)),
                summary=(result.text or "")[:_SUMMARY_LIMIT],
                key_count=len(result.data or {}),
                finding_count=counts.get(analyzer_id, 0),
                data=dict(result.data or {}) if include_data else {},
            )
        )

    severity_counts: dict[str, int] = {}
    for finding in finding_list:
        severity = getattr(finding.severity, "value", str(finding.severity))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    target_payload = {
        "name": getattr(target, "name", "") or "",
        "path": str(getattr(target, "path", "") or ""),
        "sha256": getattr(target, "sha256", "") or "",
        "size": int(getattr(target, "size", 0) or 0),
    }

    return ReportDocument(
        target=target_payload,
        generated_at=datetime.now(timezone.utc).isoformat(),
        sections=tuple(sections),
        findings=tuple(_finding_payload(item) for item in finding_list),
        counts={
            "analyzer_count": len(sections),
            "finding_count": len(finding_list),
            "severity_counts": severity_counts,
        },
    )


def _finding_payload(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "category": finding.category,
        "severity": getattr(finding.severity, "value", str(finding.severity)),
        "confidence": getattr(finding.confidence, "value", str(finding.confidence)),
        "message": finding.message,
        "remediation": finding.remediation,
        "locations": [dict(item) for item in (finding.locations or ())],
        "suppressed": bool(finding.suppressed),
    }


def render_report(
    document: ReportDocument,
    formats: Sequence[str],
    primary_format: str,
    *,
    include_data: bool = False,
) -> RenderedReport:
    """Render ``document`` into every requested format."""
    serializers = {
        "text": lambda: _render_text(document),
        "markdown": lambda: _render_markdown(document),
        "json": lambda: _render_json(document, include_data),
        "html": lambda: _render_html(document),
        "sarif": lambda: _render_sarif(document),
    }

    contents: dict[str, str] = {}
    errors: dict[str, str] = {}
    for name in formats:
        serializer = serializers.get(name)
        if serializer is None:
            errors[name] = "不支持的输出格式"
            continue
        try:
            contents[name] = serializer()
        except Exception as exc:  # pragma: no cover - 序列化异常的兜底
            errors[name] = f"{type(exc).__name__}: {exc}"

    primary = primary_format if primary_format in contents else (
        next(iter(contents)) if contents else ""
    )
    return RenderedReport(
        formats=tuple(formats),
        primary_format=primary,
        contents=contents,
        errors=errors,
        document=document,
    )


def _render_text(document: ReportDocument) -> str:
    lines = [
        "SOInsight 分析报告",
        "=" * 40,
        f"目标      : {document.target['name'] or '(未命名)'}",
        f"路径      : {document.target['path'] or '-'}",
        f"SHA-256   : {document.target['sha256'] or '-'}",
        f"生成时间  : {document.generated_at}",
        "",
        f"分析器: {document.counts['analyzer_count']} 个"
        f"，发现项: {document.counts['finding_count']} 条",
    ]
    severity_counts = document.counts.get("severity_counts") or {}
    if severity_counts:
        summary = "，".join(
            f"{name} {value}" for name, value in sorted(severity_counts.items())
        )
        lines.append(f"严重度分布: {summary}")

    lines.extend(["", "--- 分析器分节 ---"])
    if not document.sections:
        lines.append("（本次运行没有分析器产出）")
    for section in document.sections:
        lines.append(
            f"[{section.status}] {section.analyzer_id}"
            f"（字段 {section.key_count}，发现项 {section.finding_count}）"
        )
        if section.summary:
            for line in section.summary.rstrip().splitlines():
                lines.append(f"    {line}")

    if document.findings:
        lines.extend(["", "--- 发现项 ---"])
        for item in document.findings:
            marker = " (已抑制)" if item["suppressed"] else ""
            lines.append(
                f"  {item['severity'].upper():<8} {item['rule_id']}{marker}: "
                f"{item['title']}"
            )
            lines.append(f"      {item['message']}")
    return "\n".join(lines) + "\n"


def _render_markdown(document: ReportDocument) -> str:
    lines = [
        "# SOInsight 分析报告",
        "",
        "## 目标",
        "",
        f"- 名称: `{document.target['name'] or '(未命名)'}`",
        f"- 路径: `{document.target['path'] or '-'}`",
        f"- SHA-256: `{document.target['sha256'] or '-'}`",
        f"- 大小: {document.target['size']} 字节",
        f"- 生成时间: `{document.generated_at}`",
        "",
        "## 总览",
        "",
        f"- 分析器: {document.counts['analyzer_count']} 个",
        f"- 发现项: {document.counts['finding_count']} 条",
    ]
    severity_counts = document.counts.get("severity_counts") or {}
    for name, value in sorted(severity_counts.items()):
        lines.append(f"- 严重度 {name}: {value}")

    lines.extend(["", "## 分析器分节", ""])
    if not document.sections:
        lines.append("_本次运行没有分析器产出_")
    for section in document.sections:
        lines.append(
            f"### `{section.analyzer_id}` "
            f"({section.status}，发现项 {section.finding_count})"
        )
        lines.append("")
        if section.summary:
            lines.append("```text")
            lines.extend(section.summary.rstrip().splitlines())
            lines.append("```")
        else:
            lines.append("_该分析器没有输出摘要_")
        lines.append("")

    if document.findings:
        lines.extend(["## 发现项", "", "| 严重度 | 规则 | 标题 | 置信度 |", "|---|---|---|---|"])
        for item in document.findings:
            lines.append(
                f"| {item['severity']} | `{item['rule_id']}` | "
                f"{item['title']} | {item['confidence']} |"
            )
    return "\n".join(lines) + "\n"


def _render_json(document: ReportDocument, include_data: bool) -> str:
    payload = document.as_dict(include_data)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _render_html(document: ReportDocument) -> str:
    escape = html.escape
    parts = [
        "<!DOCTYPE html>",
        '<html lang="zh"><head><meta charset="utf-8">',
        "<title>SOInsight 分析报告</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.5}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}"
        "pre{background:#f6f6f6;padding:.6rem;overflow:auto}</style>",
        "</head><body>",
        "<h1>SOInsight 分析报告</h1>",
        "<h2>目标</h2><ul>",
        f"<li>名称: <code>{escape(document.target['name'])}</code></li>",
        f"<li>路径: <code>{escape(document.target['path'])}</code></li>",
        f"<li>SHA-256: <code>{escape(document.target['sha256'])}</code></li>",
        f"<li>生成时间: <code>{escape(document.generated_at)}</code></li>",
        "</ul>",
        "<h2>总览</h2>",
        f"<p>分析器 {document.counts['analyzer_count']} 个，"
        f"发现项 {document.counts['finding_count']} 条。</p>",
        "<h2>分析器分节</h2>",
    ]
    if not document.sections:
        parts.append("<p><em>本次运行没有分析器产出</em></p>")
    for section in document.sections:
        parts.append(
            f"<h3><code>{escape(section.analyzer_id)}</code> "
            f"({escape(section.status)}，发现项 {section.finding_count})</h3>"
        )
        if section.summary:
            parts.append(f"<pre>{escape(section.summary)}</pre>")
    if document.findings:
        parts.append("<h2>发现项</h2><table><tr><th>严重度</th><th>规则</th>"
                     "<th>标题</th><th>置信度</th></tr>")
        for item in document.findings:
            parts.append(
                f"<tr><td>{escape(item['severity'])}</td>"
                f"<td><code>{escape(item['rule_id'])}</code></td>"
                f"<td>{escape(item['title'])}</td>"
                f"<td>{escape(item['confidence'])}</td></tr>"
            )
        parts.append("</table>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def _render_sarif(document: ReportDocument) -> str:
    results = [
        {
            "ruleId": item["rule_id"],
            "level": "warning",
            "message": {"text": item["message"]},
            "locations": [],
            "properties": {
                "severity": item["severity"],
                "confidence": item["confidence"],
            },
        }
        for item in document.findings
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "SOInsight"}},
                "results": results,
                "properties": {
                    "target": document.target,
                    "analyzers": [
                        section.as_dict() for section in document.sections
                    ],
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
