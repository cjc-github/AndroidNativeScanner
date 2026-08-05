"""Built-in analyzer registration point."""

from ..core.analyzer import AnalyzerRegistry
from .basic import BasicFileAnalyzer


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    registry.register(BasicFileAnalyzer())
