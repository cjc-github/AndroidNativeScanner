"""SOInsight user-facing product capability domains."""

from .builtin import create_builtin_module_catalog
from .catalog import ModuleCatalog
from .model import CapabilityDefinition, ModuleDefinition

__all__ = [
    "CapabilityDefinition",
    "ModuleCatalog",
    "ModuleDefinition",
    "create_builtin_module_catalog",
]
