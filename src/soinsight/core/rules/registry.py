"""Rule registration and lookup."""

from __future__ import annotations

from .base import Rule, RuleMetadata


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        rule_id = rule.metadata.id
        if not rule_id:
            raise ValueError("Rule id cannot be empty")
        if rule_id in self._rules:
            raise ValueError(f"Rule already registered: {rule_id}")
        self._rules[rule_id] = rule

    def get(self, rule_id: str) -> Rule:
        try:
            return self._rules[rule_id]
        except KeyError as exc:
            raise KeyError(f"Rule not found: {rule_id}") from exc

    def list(self) -> list[RuleMetadata]:
        return [self._rules[key].metadata for key in sorted(self._rules)]

    def enabled_rules(self) -> list[Rule]:
        return [
            self._rules[metadata.id]
            for metadata in self.list()
            if metadata.default_enabled
        ]
