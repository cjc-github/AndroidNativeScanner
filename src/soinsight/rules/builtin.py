"""Built-in rule registration."""

from ..core.rules import RuleEngine, RuleRegistry
from .string_rules import EncodedPayloadRule, HardcodedUrlRule, SensitiveStringRule

__all__ = [
    "create_builtin_rule_registry",
    "create_default_rule_engine",
    "register_builtin_rules",
]


def register_builtin_rules(registry: RuleRegistry) -> None:
    registry.register(SensitiveStringRule())
    registry.register(HardcodedUrlRule())
    registry.register(EncodedPayloadRule())


def create_builtin_rule_registry() -> RuleRegistry:
    registry = RuleRegistry()
    register_builtin_rules(registry)
    return registry


def create_default_rule_engine() -> RuleEngine:
    return RuleEngine(create_builtin_rule_registry())
