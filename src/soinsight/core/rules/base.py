"""Security and policy rule extension contract."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..analyzer import AnalysisContext
from ..models import Finding


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    requires: tuple[str, ...] = ()
    default_enabled: bool = True


class Rule(ABC):
    metadata: RuleMetadata

    @abstractmethod
    def evaluate(self, context: AnalysisContext) -> list[Finding]:
        """Evaluate normalized analyzer results and return findings."""
