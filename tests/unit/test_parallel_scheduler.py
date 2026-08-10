"""Unit tests for parallel execution within independent DAG stages."""

import time

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.runtime import AnalysisRuntime
from soinsight.infrastructure.config import RuntimeConfig


class SlowAnalyzer(Analyzer):
    def __init__(self, analyzer_id, calls):
        self.metadata = AnalyzerMetadata(id=analyzer_id, name=analyzer_id, version="1")
        self.calls = calls

    def analyze(self, target, context):
        time.sleep(0.2)
        self.calls.append(self.metadata.id)
        return AnalysisResult(self.metadata.id, "1", AnalysisStatus.SUCCESS)


def _make_target(tmp_path) -> AnalysisTarget:
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    return AnalysisTarget(
        target_file,
        target_file.resolve(),
        "sample.so",
        6,
        "sha",
    )


def test_runtime_runs_independent_stage_in_parallel(tmp_path):
    target = _make_target(tmp_path)
    calls = []
    registry = AnalyzerRegistry()
    registry.register(SlowAnalyzer("a", calls))
    registry.register(SlowAnalyzer("b", calls))

    started = time.perf_counter()
    AnalysisRuntime(registry).execute(
        target, ("a", "b"), RuntimeConfig(jobs=2, cache_enabled=False)
    )
    duration = time.perf_counter() - started

    assert sorted(calls) == ["a", "b"]
    assert duration < 0.35
