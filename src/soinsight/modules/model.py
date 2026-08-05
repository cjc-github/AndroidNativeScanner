"""Product capability-domain models.

The product is organized by user-facing analysis domains. Analyzer, Rule,
Renderer, Scheduler, and storage remain internal technical extension points.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityDefinition:
    """One user-facing capability inside a product domain."""

    id: str
    command: str
    name: str
    description: str
    target_arguments: tuple[str, ...] = ("target",)


@dataclass(frozen=True)
class ModuleDefinition:
    """A top-level SOInsight product capability domain."""

    id: str
    name: str
    description: str
    capabilities: tuple[CapabilityDefinition, ...]

    def get_capability(self, command: str) -> CapabilityDefinition:
        for capability in self.capabilities:
            if capability.command == command:
                return capability
        raise KeyError(f"Capability not found in module '{self.id}': {command}")

    @property
    def analyzer_ids(self) -> tuple[str, ...]:
        """Capability IDs compatible with the current single-target Runtime."""
        return tuple(
            capability.id
            for capability in self.capabilities
            if capability.target_arguments == ("target",)
        )
