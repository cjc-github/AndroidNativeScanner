"""Built-in analyzer registration point."""

from ..core.analyzer import AnalyzerRegistry
from .advanced import AdvancedStringsAnalyzer
from .basic import BasicElfAnalyzer, BasicFileAnalyzer
from .dwarf import BasicDwarfAnalyzer
from .security import (
    SecurityDangerousApiAnalyzer,
    SecurityHardeningAnalyzer,
    SecurityRiskAnalyzer,
)
from .symbols import BasicSymbolsAnalyzer


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
    registry.register(BasicSymbolsAnalyzer())
    registry.register(BasicDwarfAnalyzer())
    registry.register(AdvancedStringsAnalyzer())
    registry.register(SecurityHardeningAnalyzer())
    registry.register(SecurityDangerousApiAnalyzer())
    registry.register(SecurityRiskAnalyzer())
