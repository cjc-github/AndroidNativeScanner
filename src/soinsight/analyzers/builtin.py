"""Built-in analyzer registration point."""

from ..core.analyzer import AnalyzerRegistry
from .advanced import AdvancedStringsAnalyzer
from .algorithm import AdvancedAlgorithmAnalyzer
from .basic import BasicElfAnalyzer, BasicFileAnalyzer
from .callgraph import BasicCallgraphAnalyzer
from .cfg import BasicCfgAnalyzer
from .constants import AdvancedConstantsAnalyzer
from .cpp import BasicCppAnalyzer
from .dataflow import BasicDataflowAnalyzer
from .dynamic_link import BasicDynamicAnalyzer
from .disasm import BasicDisasmAnalyzer
from .dwarf import BasicDwarfAnalyzer
from .dynamic_loading import SecurityDynamicLoadingAnalyzer
from .security import (
    SecurityDangerousApiAnalyzer,
    SecurityHardeningAnalyzer,
    SecurityRiskAnalyzer,
    SecurityVulnerabilityAnalyzer,
)
from .symbols import BasicSymbolsAnalyzer
from .types import BasicTypesAnalyzer
from .xref import BasicXrefAnalyzer


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
    registry.register(BasicDynamicAnalyzer())
    registry.register(BasicXrefAnalyzer())
    registry.register(AdvancedConstantsAnalyzer())
    registry.register(AdvancedAlgorithmAnalyzer())
    registry.register(AdvancedStringsAnalyzer())
    registry.register(SecurityHardeningAnalyzer())
    registry.register(SecurityDynamicLoadingAnalyzer())
    registry.register(SecurityDangerousApiAnalyzer())
    registry.register(SecurityRiskAnalyzer())
    registry.register(SecurityVulnerabilityAnalyzer())
