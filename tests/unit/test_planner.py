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
