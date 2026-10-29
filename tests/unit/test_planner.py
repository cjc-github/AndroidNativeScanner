from dataclasses import dataclass

import pytest

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus
from soinsight.core.runtime import DependencyCycleError, DependencyPlanner


@dataclass
class FakeAnalyzer(Analyzer):
    metadata: AnalyzerMetadata

    def analyze(self, target, context):
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
        )


def test_planner_builds_dependency_stages():
    registry = AnalyzerRegistry()
    registry.register(FakeAnalyzer(AnalyzerMetadata(id="file", name="File", version="1")))
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(
                id="elf",
                name="ELF",
                version="1",
                requires=("file",),
            )
        )
    )
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(
                id="security",
                name="Security",
                version="1",
                requires=("elf",),
            )
        )
    )

    plan = DependencyPlanner().build(("security",), registry)

    assert plan.requested == ("security",)
    assert plan.resolved == ("file", "elf", "security")
    assert [stage.analyzer_ids for stage in plan.stages] == [
        ("file",),
        ("elf",),
        ("security",),
    ]


def _registry_with_optional_consumer(**consumer_fields):
    registry = AnalyzerRegistry()
    registry.register(
        FakeAnalyzer(AnalyzerMetadata(id="basic.symbols", name="Symbols", version="1"))
    )
    registry.register(
        FakeAnalyzer(AnalyzerMetadata(id="basic.callgraph", name="Callgraph", version="1"))
    )
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(
                id="security.dangerous-api",
                name="Dangerous",
                version="1",
                requires=("basic.symbols",),
                optional_requires=("basic.callgraph",),
                **consumer_fields,
            )
        )
    )
    return registry


def test_optional_dependency_is_not_pulled_into_the_plan():
    plan = DependencyPlanner().build(
        ("security.dangerous-api",), _registry_with_optional_consumer()
    )

    assert plan.resolved == ("basic.symbols", "security.dangerous-api")
    assert "basic.callgraph" not in plan.resolved


def test_optional_dependency_orders_when_it_is_requested():
    plan = DependencyPlanner().build(
        ("security.dangerous-api", "basic.callgraph"),
        _registry_with_optional_consumer(),
    )

    assert plan.resolved.index("basic.callgraph") < plan.resolved.index(
        "security.dangerous-api"
    )


def test_optional_dependency_orders_when_pulled_in_by_a_hard_edge():
    registry = _registry_with_optional_consumer()
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(
                id="security.risk",
                name="Risk",
                version="1",
                requires=("basic.callgraph",),
            )
        )
    )

    plan = DependencyPlanner().build(
        ("security.dangerous-api", "security.risk"), registry
    )

    assert plan.resolved.index("basic.callgraph") < plan.resolved.index(
        "security.dangerous-api"
    )


def test_unregistered_optional_dependency_is_ignored():
    registry = AnalyzerRegistry()
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(
                id="consumer",
                name="Consumer",
                version="1",
                optional_requires=("missing.analyzer",),
            )
        )
    )

    plan = DependencyPlanner().build(("consumer",), registry)

    assert plan.resolved == ("consumer",)


def test_planner_rejects_dependency_cycle():
    registry = AnalyzerRegistry()
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(id="a", name="A", version="1", requires=("b",))
        )
    )
    registry.register(
        FakeAnalyzer(
            AnalyzerMetadata(id="b", name="B", version="1", requires=("a",))
        )
    )

    with pytest.raises(DependencyCycleError):
        DependencyPlanner().build(("a",), registry)
