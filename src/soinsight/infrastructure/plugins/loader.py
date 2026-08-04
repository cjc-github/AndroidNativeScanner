"""Plugin loading extension point."""

from ...core.analyzer import AnalyzerRegistry


class PluginLoader:
    """Initial no-op loader; discovery strategies can be added without changing CLI."""

    def load(self, registry: AnalyzerRegistry) -> None:
        del registry
        return None
