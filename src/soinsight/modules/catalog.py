"""Registry for top-level product capability domains."""

from collections.abc import Iterable

from .model import ModuleDefinition


class ModuleCatalog:
    def __init__(self, modules: Iterable[ModuleDefinition] = ()) -> None:
        self._modules: dict[str, ModuleDefinition] = {}
        for module in modules:
            self.register(module)

    def register(self, module: ModuleDefinition) -> None:
        if not module.id:
            raise ValueError("Module id cannot be empty")
        if module.id in self._modules:
            raise ValueError(f"Module already registered: {module.id}")
        capability_ids: set[str] = set()
        commands: set[str] = set()
        for capability in module.capabilities:
            if not capability.id.startswith(f"{module.id}."):
                raise ValueError(
                    f"Capability '{capability.id}' must be namespaced by module "
                    f"'{module.id}'"
                )
            if capability.id in capability_ids:
                raise ValueError(f"Duplicate capability id: {capability.id}")
            if capability.command in commands:
                raise ValueError(
                    f"Duplicate command in module '{module.id}': {capability.command}"
                )
            capability_ids.add(capability.id)
            commands.add(capability.command)
        self._modules[module.id] = module

    def get(self, module_id: str) -> ModuleDefinition:
        try:
            return self._modules[module_id]
        except KeyError as exc:
            raise KeyError(f"Module not found: {module_id}") from exc

    def list(self) -> list[ModuleDefinition]:
        return [self._modules[module_id] for module_id in self._modules]

    def analyzer_ids(self, module_ids: Iterable[str]) -> tuple[str, ...]:
        resolved: list[str] = []
        seen: set[str] = set()
        for module_id in module_ids:
            for analyzer_id in self.get(module_id).analyzer_ids:
                if analyzer_id not in seen:
                    resolved.append(analyzer_id)
                    seen.add(analyzer_id)
        return tuple(resolved)
