"""Plugin loading extension point."""

import importlib.metadata
from collections.abc import Iterable

from ...core.analyzer import Analyzer, AnalyzerRegistry


class PluginLoader:
    """Load analyzer plugins from the Python entry point group ``soinsight.analyzers``.

    Each entry point must load a callable returning one Analyzer instance or an
    iterable of Analyzer instances.
    """

    group = "soinsight.analyzers"

    def load(self, registry: AnalyzerRegistry) -> None:
        for entry_point in importlib.metadata.entry_points(group=self.group):
            factory = entry_point.load()
            loaded = factory()
            analyzers = (
                loaded
                if isinstance(loaded, Iterable) and not isinstance(loaded, Analyzer)
                else (loaded,)
            )
            for analyzer in analyzers:
                registry.register(analyzer)
