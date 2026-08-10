"""Unit tests for entry-point-based analyzer plugin discovery."""

from dataclasses import dataclass

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus
from soinsight.infrastructure.plugins.loader import PluginLoader


@dataclass
class PluginAnalyzer(Analyzer):
    metadata = AnalyzerMetadata("plugin.sample", "Plugin Sample", "1")

    def analyze(self, target, context):
        return AnalysisResult("plugin.sample", "1", AnalysisStatus.SUCCESS)


class FakeEntryPoint:
    name = "plugin-sample"

    def load(self):
        return lambda: PluginAnalyzer()


def test_plugin_loader_registers_entry_point_analyzer(monkeypatch):
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda group=None: [FakeEntryPoint()] if group == "soinsight.analyzers" else [],
    )
    registry = AnalyzerRegistry()

    PluginLoader().load(registry)

    assert registry.contains("plugin.sample")
