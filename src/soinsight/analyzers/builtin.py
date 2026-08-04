"""Built-in analyzer registration point.

Concrete ELF analyzers are intentionally not migrated in the framework-only
phase. Future analyzers register here without changing the runtime.
"""

from ..core.analyzer import AnalyzerRegistry


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    del registry
    return None
