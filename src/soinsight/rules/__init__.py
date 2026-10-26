"""Built-in product rules.

Rules turn normalized analyzer facts into findings. The engine contract
lives in :mod:`soinsight.core.rules`; this package registers the rules that
ship with the product itself. ``security.risk`` deliberately stays outside:
it is an analyzer so that the dependency planner can order it in the DAG.
"""

from .builtin import (
    create_builtin_rule_registry,
    create_default_rule_engine,
    register_builtin_rules,
)
from .string_rules import EncodedPayloadRule, HardcodedUrlRule, SensitiveStringRule

__all__ = [
    "EncodedPayloadRule",
    "HardcodedUrlRule",
    "SensitiveStringRule",
    "create_builtin_rule_registry",
    "create_default_rule_engine",
    "register_builtin_rules",
]
