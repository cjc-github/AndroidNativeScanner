"""Unit tests for the built-in advanced.strings consumption rules."""

from pathlib import Path

from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.rules import RuleEngine
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.rules import (
    EncodedPayloadRule,
    HardcodedUrlRule,
    SensitiveStringRule,
    create_builtin_rule_registry,
)


def _context(strings_data: dict | None) -> AnalysisContext:
    target = AnalysisTarget(
        path=Path("sample.so"), real_path=Path("/tmp/sample.so"),
        name="sample.so", size=1, sha256="0" * 64,
    )
    context = AnalysisContext("run", target, RuntimeConfig())
    if strings_data is not None:
        context.add_result(
            AnalysisResult(
                analyzer_id="advanced.strings",
                analyzer_version="1.0.0",
                status=AnalysisStatus.SUCCESS,
                data=strings_data,
            )
        )
    return context


def _run(strings_data: dict):
    context = _context(strings_data)
    engine = RuleEngine(create_builtin_rule_registry())
    engine.evaluate(context)
    return context


def test_rule_metadata_matches_the_design_namespace():
    assert SensitiveStringRule.metadata.id == "security.sensitive-string"
    assert HardcodedUrlRule.metadata.id == "security.hardcoded-url"
    assert EncodedPayloadRule.metadata.id == "security.encoded-payload"
    for rule in (SensitiveStringRule(), HardcodedUrlRule(), EncodedPayloadRule()):
        assert rule.metadata.requires == ("advanced.strings",)


def test_rules_skip_silently_without_strings_data():
    context = _context(None)
    engine = RuleEngine(create_builtin_rule_registry())

    engine.evaluate(context)

    assert context.findings == []
    assert context.diagnostics == []


def test_sensitive_rule_uses_v1_labels_and_slugs():
    context = _run(
        {
            "classified": {
                "sensitive": {
                    "count": 2,
                    "hits": [
                        {"label": "Google API Key", "value": "AIzaSy" + "A" * 37,
                         "offset": "0x10", "section": ".rodata"},
                        {"label": "Password/Token", "value": "password=admin",
                         "offset": "0x30", "section": None},
                    ],
                }
            }
        }
    )

    by_rule = {finding.rule_id: finding for finding in context.findings}
    assert set(by_rule) == {
        "security.sensitive-string.google-api-key",
        "security.sensitive-string.password-token",
    }
    precise = by_rule["security.sensitive-string.google-api-key"]
    assert precise.severity.value == "high"
    assert precise.confidence.value == "high"
    generic = by_rule["security.sensitive-string.password-token"]
    assert generic.severity.value == "medium"
    assert generic.confidence.value == "low"


def test_url_rule_reports_low_severity_facts():
    context = _run(
        {
            "classified": {
                "url": {
                    "count": 1,
                    "hits": [
                        {"value": "https://api.example.com", "offset": "0x0",
                         "section": ".rodata"}
                    ],
                }
            }
        }
    )

    finding = context.findings[0]
    assert finding.rule_id == "security.hardcoded-url"
    assert finding.severity.value == "info"
    assert finding.confidence.value == "high"
    assert finding.fingerprint == "url:https://api.example.com"
    assert finding.locations[0]["offset"] == "0x0"
    assert finding.locations[0]["section"] == ".rodata"


def test_encoded_payload_rule_reports_base64_fact():
    context = _run(
        {
            "classified": {
                "base64": {
                    "count": 1,
                    "hits": [
                        {"value": "cHJpbnRhYmxlIHBheWxvYWQ=", "offset": "0x8",
                         "section": ".rodata", "decoded": "printable payload"}
                    ],
                }
            }
        }
    )

    finding = context.findings[0]
    assert finding.rule_id == "security.encoded-payload"
    assert finding.severity.value == "low"
    assert finding.confidence.value == "medium"
    assert finding.evidence[0]["decoded"] == "printable payload"


def test_findings_are_traced_by_fingerprint_for_dedup():
    duplicated = {
        "classified": {
            "url": {
                "count": 2,
                "hits": [
                    {"value": "https://dup.example", "offset": "0x0", "section": None},
                ],
            }
        }
    }
    context = _run(duplicated)

    assert len(context.findings) == 1
    assert context.findings[0].fingerprint == "url:https://dup.example"


def test_broken_rule_becomes_a_diagnostic():
    class Broken(HardcodedUrlRule):
        metadata = HardcodedUrlRule.metadata

        def evaluate(self, context):
            raise RuntimeError("boom")

    context = _context(
        {"classified": {"url": {"count": 1, "hits": [{"value": "https://boom.example",
                                                      "offset": "0x0", "section": None}]}}}
    )
    registry = create_builtin_rule_registry()
    # Replace the built-in rule with the broken variant (same id) to keep
    # registration simple while exercising the engine's exception handling.
    registry._rules["security.hardcoded-url"] = Broken()

    RuleEngine(registry).evaluate(context)

    codes = [diagnostic.code for diagnostic in context.diagnostics]
    assert "RULE_EXCEPTION" in codes
