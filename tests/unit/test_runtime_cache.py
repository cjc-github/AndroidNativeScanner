"""Unit tests for the file-backed runtime result cache."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Finding,
    Severity,
)
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


def test_runtime_cache_round_trips_finding_object(tmp_path):
    target_file = tmp_path / "app"
    target_file.write_bytes(b"placeholder")
    target = AnalysisTarget(target_file, target_file.resolve(), "app", 11, "sha")
    cache = RuntimeCache(RuntimeConfig(cache_dir=tmp_path / "cache"))
    result = AnalysisResult(
        analyzer_id="security.hardening",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={"hardening_summary": {"finding_count": 1}},
        findings=[
            Finding(
                rule_id="security.hardening.executable-elf",
                title="Executable ELF lacks shared-object hardening baseline",
                category="hardening",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message="ELF type is EXEC rather than DYN.",
            )
        ],
    )

    cache.put(target, result)
    cached = cache.get(target, "security.hardening", "1.0.0")

    assert cached is not None
    assert isinstance(cached.findings[0], Finding)
    assert cached.findings[0].rule_id == "security.hardening.executable-elf"
    assert cached.findings[0].severity is Severity.MEDIUM


@dataclass
class RecordingAnalyzer(Analyzer):
    metadata: AnalyzerMetadata
    calls: list[str]
    findings: list = field(default_factory=list)

    def analyze(self, target, context):
        self.calls.append(self.metadata.id)
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"target": target.name},
            findings=self.findings,
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


def test_runtime_caches_and_hits_result_with_findings(tmp_path):
    calls = []
    finding = Finding(
        rule_id="security.hardening.executable-elf",
        title="Executable ELF lacks shared-object hardening baseline",
        category="hardening",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        message="ELF type is EXEC rather than DYN.",
    )
    registry = AnalyzerRegistry()
    registry.register(
        RecordingAnalyzer(
            AnalyzerMetadata(id="security.hardening", name="Hardening", version="1"),
            calls,
            findings=[finding],
        )
    )
    config = RuntimeConfig(cache_enabled=True, cache_dir=tmp_path / "cache")

    first = AnalysisRuntime(registry).execute(
        _make_target(tmp_path), ("security.hardening",), config
    )
    assert calls == ["security.hardening"]
    assert (
        first.results["security.hardening"].findings[0].rule_id
        == "security.hardening.executable-elf"
    )

    second = AnalysisRuntime(registry).execute(
        _make_target(tmp_path), ("security.hardening",), config
    )
    assert calls == ["security.hardening"]
    assert second.results["security.hardening"].cache_hit is True
    assert (
        second.results["security.hardening"].findings[0].rule_id
        == "security.hardening.executable-elf"
    )


def test_runtime_cache_round_trips_text_output(tmp_path):
    """``text`` is part of the cached payload, not something rebuilt on load."""
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    cache = RuntimeCache(RuntimeConfig(cache_dir=tmp_path / "cache"))
    result = AnalysisResult(
        analyzer_id="basic.file",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={"size": 6},
        text="=== 文件信息 ===\n大小: 6 字节",
    )

    cache.put(target, result)
    cached = cache.get(target, "basic.file", "1.0.0")

    assert cached is not None
    assert cached.text == "=== 文件信息 ===\n大小: 6 字节"


def test_runtime_cache_reads_legacy_payload_without_text(tmp_path):
    """Files written before ``text`` existed must still load, with an empty text."""
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    cache = RuntimeCache(RuntimeConfig(cache_dir=tmp_path / "cache"))
    cache.put(
        target,
        AnalysisResult(
            analyzer_id="basic.file",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"size": 6},
            text="=== 文件信息 ===",
        ),
    )

    path = cache._path(target, "basic.file", "1.0.0")
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    del payload["text"]  # simulate a cache entry from before the field existed
    Path(path).write_text(json.dumps(payload), encoding="utf-8")

    cached = cache.get(target, "basic.file", "1.0.0")

    assert cached is not None
    assert cached.text == ""
    assert cached.data == {"size": 6}


@dataclass
class TextRecordingAnalyzer(Analyzer):
    """Records analyze() and format_text() calls so cache hits can be observed."""

    metadata: AnalyzerMetadata
    analyzed: list[str]
    formatted: list[str]

    def analyze(self, target, context):
        self.analyzed.append(self.metadata.id)
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"target": target.name},
        )

    def format_text(self, result):
        self.formatted.append(result.analyzer_id)
        return "=== 缓存的文本 ==="


def test_runtime_reuses_cached_text_instead_of_reformatting(tmp_path):
    """A cache hit carries its own text, so format_text is not called again."""
    analyzed: list[str] = []
    formatted: list[str] = []
    registry = AnalyzerRegistry()
    registry.register(
        TextRecordingAnalyzer(
            AnalyzerMetadata(id="basic.file", name="File", version="1"),
            analyzed,
            formatted,
        )
    )
    config = RuntimeConfig(cache_enabled=True, cache_dir=tmp_path / "cache")

    first = AnalysisRuntime(registry).execute(
        _make_target(tmp_path), ("basic.file",), config
    )
    assert analyzed == ["basic.file"]
    assert formatted == ["basic.file"]
    assert first.results["basic.file"].text == "=== 缓存的文本 ==="

    second = AnalysisRuntime(registry).execute(
        _make_target(tmp_path), ("basic.file",), config
    )
    assert analyzed == ["basic.file"], "cache hit must not re-run the analyzer"
    assert formatted == ["basic.file"], "cache hit must not re-render the text"
    assert second.results["basic.file"].cache_hit is True
    assert second.results["basic.file"].text == "=== 缓存的文本 ==="
