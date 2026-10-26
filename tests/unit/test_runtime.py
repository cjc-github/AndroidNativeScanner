from dataclasses import dataclass
from pathlib import Path

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.runtime import AnalysisRuntime
from soinsight.infrastructure.config import RuntimeConfig


@dataclass
class RecordingAnalyzer(Analyzer):
    metadata: AnalyzerMetadata
    calls: list[str]
    fail: bool = False

    def analyze(self, target, context):
        self.calls.append(self.metadata.id)
        if self.fail:
            raise RuntimeError("expected failure")
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"target": target.name},
        )


def make_target() -> AnalysisTarget:
    return AnalysisTarget(
        path=Path("sample.so"),
        real_path=Path("/tmp/sample.so"),
        name="sample.so",
        size=1,
        sha256="0" * 64,
    )


def test_runtime_executes_dependencies_in_order():
    calls = []
    registry = AnalyzerRegistry()
    registry.register(
        RecordingAnalyzer(AnalyzerMetadata(id="file", name="File", version="1"), calls)
    )
    registry.register(
        RecordingAnalyzer(
            AnalyzerMetadata(
                id="elf", name="ELF", version="1", requires=("file",)
            ),
            calls,
        )
    )

    result = AnalysisRuntime(registry).execute(
        make_target(), ("elf",), RuntimeConfig()
    )

    assert calls == ["file", "elf"]
    assert result.status is AnalysisStatus.SUCCESS
    assert result.resolved_analyzers == ("file", "elf")


def test_runtime_contains_analyzer_failure():
    calls = []
    registry = AnalyzerRegistry()
    registry.register(
        RecordingAnalyzer(
            AnalyzerMetadata(id="file", name="File", version="1"),
            calls,
            fail=True,
        )
    )
    registry.register(
        RecordingAnalyzer(
            AnalyzerMetadata(
                id="elf", name="ELF", version="1", requires=("file",)
            ),
            calls,
        )
    )

    result = AnalysisRuntime(registry).execute(
        make_target(), ("elf",), RuntimeConfig()
    )

    assert calls == ["file"]
    assert result.status is AnalysisStatus.FAILED
    assert result.results["file"].status is AnalysisStatus.FAILED
    assert result.results["elf"].status is AnalysisStatus.SKIPPED


@dataclass
class TextAnalyzer(Analyzer):
    """Analyzer whose ``format_text`` behaviour is controlled by the test."""

    metadata: AnalyzerMetadata
    text: str | None = "=== 文本化结果 ==="
    boom: bool = False

    def analyze(self, target, context):
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"target": target.name},
        )

    def format_text(self, result):
        if self.boom:
            raise RuntimeError("formatter exploded")
        return self.text


def _run_single(analyzer: Analyzer):
    registry = AnalyzerRegistry()
    registry.register(analyzer)
    return AnalysisRuntime(registry).execute(
        make_target(), (analyzer.metadata.id,), RuntimeConfig()
    )


def test_runtime_attaches_analyzer_text_output():
    analyzer = TextAnalyzer(AnalyzerMetadata(id="basic.file", name="File", version="1"))
    scan = _run_single(analyzer)
    assert scan.results["basic.file"].text == "=== 文本化结果 ==="


def test_runtime_leaves_text_empty_when_formatter_returns_none():
    analyzer = TextAnalyzer(
        AnalyzerMetadata(id="basic.file", name="File", version="1"), text=None
    )
    scan = _run_single(analyzer)
    assert scan.results["basic.file"].text == ""


def test_runtime_tolerates_formatter_exception():
    """A broken formatter must not fail the analysis; the text stays empty."""
    analyzer = TextAnalyzer(
        AnalyzerMetadata(id="basic.file", name="File", version="1"), boom=True
    )
    scan = _run_single(analyzer)
    assert scan.results["basic.file"].status is AnalysisStatus.SUCCESS
    assert scan.results["basic.file"].text == ""
