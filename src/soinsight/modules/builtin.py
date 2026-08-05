"""Built-in product capability domains."""

from .advanced import MODULE as ADVANCED
from .ai import MODULE as AI
from .automation import MODULE as AUTOMATION
from .basic import MODULE as BASIC
from .catalog import ModuleCatalog
from .dynamic import MODULE as DYNAMIC
from .security import MODULE as SECURITY


def create_builtin_module_catalog() -> ModuleCatalog:
    return ModuleCatalog((BASIC, ADVANCED, SECURITY, DYNAMIC, AI, AUTOMATION))


__all__ = [
    "ADVANCED",
    "AI",
    "AUTOMATION",
    "BASIC",
    "DYNAMIC",
    "SECURITY",
    "create_builtin_module_catalog",
]
