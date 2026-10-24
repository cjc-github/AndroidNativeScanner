"""Built-in analyzer registration point."""

from ..core.analyzer import AnalyzerRegistry
from .basic import BasicElfAnalyzer, BasicFileAnalyzer
from .security import SecurityHardeningAnalyzer
from .symbols import BasicSymbolsAnalyzer


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
    registry.register(BasicSymbolsAnalyzer())
    registry.register(SecurityHardeningAnalyzer())
