from dataclasses import dataclass
from pathlib import Path

from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Finding,
    Severity,
)
from soinsight.core.rules import Rule, RuleEngine, RuleMetadata, RuleRegistry
from soinsight.infrastructure.config import RuntimeConfig


@dataclass
class FakeRule(Rule):
    metadata = RuleMetadata(
        id="test-rule",
        name="Test rule",
        requires=("elf",),
    )

    def evaluate(self, context):
        return [
            Finding(
                rule_id="TEST-001",
                title="Test finding",
                category="test",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                message="framework rule executed",
            )
        ]


def test_rule_engine_consumes_analyzer_results():
    target = AnalysisTarget(
        path=Path("sample.so"),
        real_path=Path("/tmp/sample.so"),
        name="sample.so",
        size=1,
        sha256="0" * 64,
    )
    context = AnalysisContext("run", target, RuntimeConfig())
    context.add_result(
        AnalysisResult(
            analyzer_id="elf",
            analyzer_version="1",
            status=AnalysisStatus.SUCCESS,
        )
    )
    registry = RuleRegistry()
    registry.register(FakeRule())

    RuleEngine(registry).evaluate(context)

    assert [finding.rule_id for finding in context.findings] == ["TEST-001"]
