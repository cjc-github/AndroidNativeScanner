"""Unit tests for the security.risk analyzer."""

import json
from pathlib import Path

from soinsight.analyzers.security import SecurityRiskAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Finding,
    Severity,
)
from soinsight.infrastructure.config import RuntimeConfig


def _empty_classified() -> dict:
    return {
        "url": {"count": 0, "hits": []},
        "sensitive": {"count": 0, "hits": []},
        "base64": {"count": 0, "hits": []},
    }


def _upstream(classified: dict | None = None, findings=None) -> dict[str, AnalysisResult]:
    """Minimal upstream results matching the analyzer's declared requires."""
    return {
        "advanced.strings": AnalysisResult(
            analyzer_id="advanced.strings",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"classified": classified or _empty_classified()},
        ),
        "security.hardening": AnalysisResult(
            analyzer_id="security.hardening",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"hardening_summary": {"finding_count": len(findings or [])}},
            findings=list(findings or []),
        ),
        "security.dangerous-api": AnalysisResult(
            analyzer_id="security.dangerous-api",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={},
            findings=[],
        ),
    }


def _context(results: dict[str, AnalysisResult], **extra) -> AnalysisContext:
    path = Path("sample.so")
    target = AnalysisTarget(
        path=path, real_path=path, name="libsample.so", size=1, sha256="test"
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    for result in results.values():
        context.add_result(result)
    return context


def _finding(
    rule_id: str,
    severity: Severity = Severity.MEDIUM,
    fingerprint: str = "",
    category: str = "hardening",
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Title {rule_id}",
        category=category,
        severity=severity,
        confidence=confidence,
        message=f"Message {rule_id}",
        fingerprint=fingerprint,
    )


def _analyze(results, **extra):
    context = _context(results, **extra)
    return SecurityRiskAnalyzer().analyze(context.target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("security").get_capability(
        "risk"
    )
    assert SecurityRiskAnalyzer.metadata.id == capability.id
    assert SecurityRiskAnalyzer.metadata.requires == (
        "security.hardening",
        "security.dangerous-api",
        "advanced.strings",
    )


def test_analyzer_dedupes_by_fingerprint():
    duplicate = _finding("security.hardening.exec-stack", fingerprint="exec-stack")
    results = _upstream(findings=[duplicate, duplicate])

    result = _analyze(results)

    assert result.data["finding_count"] == 2
    assert result.data["unique_finding_count"] == 1
    assert result.data["duplicate_count"] == 1


def test_analyzer_falls_back_to_message_identity_without_fingerprints():
    same_message = _finding("security.hardening.same")
    results = _upstream(findings=[same_message, same_message])

    result = _analyze(results)

    assert result.data["unique_finding_count"] == 1


def test_analyzer_weights_by_severity_with_overrides():
    findings = [
        _finding("a.high", Severity.HIGH),
        _finding("b.low", Severity.LOW),
    ]
    results = _upstream(findings=findings)

    result = _analyze(results)

    assert result.data["risk_score"] == 8 + 2
    assert result.data["risk_level"] == "medium"

    adjusted = _analyze(
        results,
        capability_options={
            "security.risk": {"severity_weights": {"high": "0", "low": "10"}}
        },
    )
    assert adjusted.data["risk_score"] == 10


def test_analyzer_scores_string_indicators_with_v1_weights():
    strings_classified = {
        "url": {"count": 2, "hits": []},
        "base64": {"count": 1, "hits": []},
        "sensitive": {
            "count": 2,
            "hits": [
                {"label": "GitHub Token", "value": "ghp_x", "offset": "0x1",
                 "section": None},
                {"label": "Password", "value": "password=x", "offset": "0x2",
                 "section": None},
            ],
        },
    }
    results = _upstream(strings_classified)

    result = _analyze(results)

    # url=2*2, base64=3, and the sensitive labels follow the V1 ladder:
    # Token=4 while a plain credential label scores the generic 2.
    assert result.data["risk_score"] == 4 + 3 + 4 + 2
    indicators = result.data["string_indicators"]
    assert indicators["url_count"] == 2
    assert indicators["url_score"] == 4
    assert indicators["sensitive_count"] == 2
    assert indicators["sensitive_score"] == 6
    assert indicators["base64_count"] == 1
    assert indicators["base64_score"] == 3


def test_analyzer_indicator_counts_survive_hit_caps():
    strings_classified = {
        "url": {"count": 1, "hits": []},
        "base64": {"count": 0, "hits": []},
        "sensitive": {
            "count": 3,
            "hits": [
                {"label": "Password", "value": "a", "offset": "0x0", "section": None}
            ],
        },
    }
    result = _analyze(_upstream(strings_classified))

    indicators = result.data["string_indicators"]
    assert indicators["url_count"] == 1
    assert indicators["sensitive_count"] == 3


def test_analyzer_ranks_top_findings_by_severity():
    findings = [
        _finding("z.low", Severity.LOW),
        _finding("a.critical", Severity.CRITICAL),
        _finding("m.high", Severity.HIGH),
    ]
    results = _upstream(findings=findings)

    result = _analyze(results)

    top = [item["rule_id"] for item in result.data["top_findings"]]
    assert top == ["a.critical", "m.high", "z.low"]


def test_analyzer_reports_empty_upstream_data():
    result = _analyze(_upstream())

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["risk_score"] == 0
    assert result.data["risk_level"] == "low"
    assert result.data["top_findings"] == []


def test_analyzer_emits_no_findings_of_its_own():
    results = _upstream(findings=[_finding("security.hardening.x", fingerprint="x")])

    result = _analyze(results)

    assert result.findings == []


def test_analyzer_result_is_json_serializable():
    results = _upstream(findings=[_finding("security.hardening.x", fingerprint="x")])

    payload = json.dumps(_analyze(results).data)
    assert "risk_level" in payload
