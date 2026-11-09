"""Unit tests for automation.report."""

import json

from soinsight.analyzers.automation_report import AutomationReportAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Finding,
    Severity,
    Confidence,
)
from soinsight.infrastructure.config import RuntimeConfig


def _target():
    return AnalysisTarget(
        path=None, real_path=None, name="libsample.so", size=0, sha256="test"
    )


def _finding(rule_id="security.hardening.missing-relro"):
    return Finding(
        rule_id=rule_id,
        title="缺少 RELRO",
        category="hardening",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        message="partial relro",
        fingerprint="fp-1",
    )


def _context(results=None, findings=None, **options):
    target = _target()
    context = AnalysisContext("run", target, RuntimeConfig(extra=options))
    for analyzer_id, data in (results or {}).items():
        context.add_result(
            AnalysisResult(
                analyzer_id=analyzer_id,
                analyzer_version="1.0.0",
                status=AnalysisStatus.SUCCESS,
                data=data,
            )
        )
    if findings:
        context.add_findings(findings)
    return context, target


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("automation").get_capability(
        "report"
    )
    assert capability.id == AutomationReportAnalyzer.metadata.id


def test_report_summarises_results_and_findings():
    context, target = _context(
        results={
            "basic.file": {"size": 10},
            "security.hardening": {"hardening_summary": {}},
        },
        findings=[_finding()],
    )

    result = AutomationReportAnalyzer().analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["analyzer_count"] == 2
    assert result.data["finding_count"] == 1
    assert result.data["target"] == "libsample.so"


def test_markdown_report_names_the_target_and_the_analyzers():
    context, target = _context(
        results={"basic.file": {"size": 10}, "basic.elf": {"machine": "AARCH64"}},
    )

    result = AutomationReportAnalyzer().analyze(target, context)
    text = result.data["report_text"]

    assert "libsample.so" in text
    assert "basic.file" in text
    assert "basic.elf" in text


def test_json_report_is_parseable():
    context, target = _context(results={"basic.file": {"size": 10}})

    result = AutomationReportAnalyzer().analyze(target, context)
    payload = json.loads(result.data["report_by_format"]["json"])

    assert payload["counts"]["analyzer_count"] == 1
    assert payload["sections"][0]["analyzer_id"] == "basic.file"
    assert payload["target"]["name"] == "libsample.so"


def test_unknown_format_is_recorded_as_an_error():
    context, target = _context(
        results={"basic.file": {"size": 10}},
        capability_options={"automation.report": {"formats": ["markdown", "nope"]}},
    )

    result = AutomationReportAnalyzer().analyze(target, context)

    assert "nope" in result.data["format_errors"]
    assert "nope" not in result.data["report_by_format"]
    assert any(
        diagnostic.code == "REPORT_FORMAT_FAILED" for diagnostic in result.diagnostics
    )


def test_publish_writes_the_report_files(tmp_path):
    context, target = _context(
        results={"basic.file": {"size": 10}},
        capability_options={
            "automation.report": {
                "publish": True,
                "reports_root": str(tmp_path),
                "formats": ["markdown", "json"],
            }
        },
    )

    result = AutomationReportAnalyzer().analyze(target, context)

    assert result.data["published"] is True
    written = sorted(path.name for path in tmp_path.rglob("*") if path.is_file())
    assert "index.md" in written
    assert "index.json" in written


def test_publish_is_off_by_default():
    context, target = _context(results={"basic.file": {"size": 10}})

    result = AutomationReportAnalyzer().analyze(target, context)

    assert result.data["published"] is False
    assert result.data["artifacts"] == []


def test_no_results_still_succeeds():
    context, target = _context()

    result = AutomationReportAnalyzer().analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["analyzer_count"] == 0


def test_format_text_summarizes_without_repeating_the_document():
    context, target = _context(results={"basic.file": {"size": 10}})

    result = AutomationReportAnalyzer().analyze(target, context)
    text = AutomationReportAnalyzer().format_text(result)

    assert "报告自动化" in text
    assert "libsample.so" in text
    assert text != result.data["report_text"]


def test_format_text_is_none_for_a_failed_result():
    context, target = _context(results={"basic.file": {"size": 10}})
    result = AutomationReportAnalyzer().analyze(target, context)
    result.status = AnalysisStatus.FAILED

    assert AutomationReportAnalyzer().format_text(result) is None


def test_sections_attribute_findings_to_their_analyzer():
    context, target = _context(
        results={"security.hardening": {}, "basic.file": {}},
        findings=[_finding("security.hardening.missing-relro")],
    )

    result = AutomationReportAnalyzer().analyze(target, context)
    sections = {item["analyzer_id"]: item for item in result.data["sections"]}

    assert sections["security.hardening"]["finding_count"] == 1
    assert sections["basic.file"]["finding_count"] == 0


def test_the_report_is_ordered_after_the_analyzers_it_summarizes():
    """The report is a view over the other analyzers, so it must run last.

    The registry is built from the analyzer classes rather than from the
    built-in registration, so the test states the rule on its own instead
    of depending on which analyzers happen to be registered.
    """
    from soinsight.core.analyzer.registry import AnalyzerRegistry
    from soinsight.core.runtime.planner import DependencyPlanner

    from soinsight.analyzers.automation_report import AutomationReportAnalyzer
    from soinsight.analyzers.basic import BasicElfAnalyzer, BasicFileAnalyzer
    from soinsight.analyzers.symbols import BasicSymbolsAnalyzer

    registry = AnalyzerRegistry()
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
    registry.register(BasicSymbolsAnalyzer())
    registry.register(AutomationReportAnalyzer())

    plan = DependencyPlanner().build(
        ("basic.file", "basic.symbols", "automation.report"), registry
    )

    stages = [tuple(stage.analyzer_ids) for stage in plan.stages]
    last = stages[-1]

    assert "automation.report" in last
    assert "basic.file" not in last
    assert "basic.symbols" not in last


def test_the_report_summarizes_the_analyzers_that_ran_before_it():
    from soinsight.core.analyzer.registry import AnalyzerRegistry
    from soinsight.core.runtime import AnalysisRuntime
    from soinsight.infrastructure.config import RuntimeConfig

    from soinsight.analyzers.automation_report import AutomationReportAnalyzer
    from soinsight.analyzers.basic import BasicElfAnalyzer, BasicFileAnalyzer

    registry = AnalyzerRegistry()
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
    registry.register(AutomationReportAnalyzer())
    runtime = AnalysisRuntime(registry)
    target = AnalysisTarget(
        path=None, real_path=None, name="libsample.so", size=0, sha256="test"
    )

    result = runtime.execute(
        target=target,
        analyzer_ids=("basic.file", "basic.elf", "automation.report"),
        config=RuntimeConfig(extra={}),
    )

    report = result.results["automation.report"]
    assert report.data["analyzer_count"] == 2
    assert {item["analyzer_id"] for item in report.data["sections"]} == {
        "basic.file",
        "basic.elf",
    }
