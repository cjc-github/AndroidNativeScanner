"""Unit tests for the file-backed runtime result cache."""

from dataclasses import dataclass

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.runtime import AnalysisRuntime
from soinsight.core.runtime.cache import RuntimeCache
from soinsight.infrastructure.config import RuntimeConfig


def test_runtime_cache_round_trips_analysis_result(tmp_path):
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    cache = RuntimeCache(RuntimeConfig(cache_dir=tmp_path / "cache"))
    result = AnalysisResult(
        analyzer_id="basic.file",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={"size": 6},
    )

    cache.put(target, result)
    cached = cache.get(target, "basic.file", "1.0.0")

    assert cached is not None
    assert cached.cache_hit is True
    assert cached.data == {"size": 6}


@dataclass
class RecordingAnalyzer(Analyzer):
    metadata: AnalyzerMetadata
    calls: list[str]

    def analyze(self, target, context):
        self.calls.append(self.metadata.id)
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"target": target.name},
        )


def _make_target(tmp_path) -> AnalysisTarget:
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    return AnalysisTarget(
        path=target_file,
        real_path=target_file.resolve(),
        name="sample.so",
        size=len(target_file.read_bytes()),
        sha256="0" * 64,
    )


def test_runtime_uses_cached_result_on_second_run(tmp_path):
    calls = []
    registry = AnalyzerRegistry()
    registry.register(
        RecordingAnalyzer(AnalyzerMetadata(id="basic.file", name="File", version="1"), calls)
    )
    config = RuntimeConfig(cache_enabled=True, cache_dir=tmp_path / "cache")

    AnalysisRuntime(registry).execute(_make_target(tmp_path), ("basic.file",), config)
    assert calls == ["basic.file"]

    AnalysisRuntime(registry).execute(_make_target(tmp_path), ("basic.file",), config)
    assert calls == ["basic.file"]
