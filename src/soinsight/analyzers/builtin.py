"""Built-in analyzer registration point."""

from ..core.analyzer import AnalyzerRegistry
from .basic import BasicElfAnalyzer, BasicFileAnalyzer


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
