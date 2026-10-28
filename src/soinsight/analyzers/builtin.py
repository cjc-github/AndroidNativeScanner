"""Built-in analyzer registration point."""

from ..core.analyzer import AnalyzerRegistry
from .advanced import AdvancedStringsAnalyzer
from .basic import BasicElfAnalyzer, BasicFileAnalyzer
from .callgraph import BasicCallgraphAnalyzer
from .cfg import BasicCfgAnalyzer
from .constants import AdvancedConstantsAnalyzer
from .cpp import BasicCppAnalyzer
from .dataflow import BasicDataflowAnalyzer
from .disasm import BasicDisasmAnalyzer
from .dwarf import BasicDwarfAnalyzer
from .security import (
    SecurityDangerousApiAnalyzer,
    SecurityHardeningAnalyzer,
    SecurityRiskAnalyzer,
    SecurityVulnerabilityAnalyzer,
)
from .symbols import BasicSymbolsAnalyzer
from .types import BasicTypesAnalyzer


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
    registry.register(BasicSymbolsAnalyzer())
    registry.register(BasicDwarfAnalyzer())
    registry.register(BasicTypesAnalyzer())
    registry.register(BasicCppAnalyzer())
    registry.register(BasicDisasmAnalyzer())
    registry.register(BasicCfgAnalyzer())
    registry.register(BasicCallgraphAnalyzer())
    registry.register(BasicDataflowAnalyzer())
    registry.register(AdvancedConstantsAnalyzer())
    registry.register(AdvancedStringsAnalyzer())
    registry.register(SecurityHardeningAnalyzer())
    registry.register(SecurityDangerousApiAnalyzer())
    registry.register(SecurityRiskAnalyzer())
    registry.register(SecurityVulnerabilityAnalyzer())
