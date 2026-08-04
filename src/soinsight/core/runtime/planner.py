"""Dependency-aware analysis plan builder."""

from ..analyzer import AnalyzerNotFoundError, AnalyzerRegistry
from .plan import AnalysisPlan, ExecutionStage


class PlanningError(ValueError):
    pass


class DependencyCycleError(PlanningError):
    pass


class DependencyPlanner:
    def build(
        self,
        requested: tuple[str, ...] | list[str],
        registry: AnalyzerRegistry,
    ) -> AnalysisPlan:
        requested_ids = tuple(dict.fromkeys(requested))
        graph: dict[str, set[str]] = {}
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(analyzer_id: str, path: tuple[str, ...]) -> None:
            if analyzer_id in visiting:
                chain = " -> ".join((*path, analyzer_id))
                raise DependencyCycleError(f"Analyzer dependency cycle: {chain}")
            if analyzer_id in visited:
                return
            try:
                analyzer = registry.get(analyzer_id)
            except AnalyzerNotFoundError as exc:
                parent = path[-1] if path else "request"
                raise PlanningError(
                    f"Missing analyzer '{analyzer_id}' required by '{parent}'"
                ) from exc

            visiting.add(analyzer_id)
            dependencies = set(analyzer.metadata.requires)
            graph[analyzer_id] = dependencies
            for dependency_id in sorted(dependencies):
                visit(dependency_id, (*path, analyzer_id))
            visiting.remove(analyzer_id)
            visited.add(analyzer_id)

        for analyzer_id in requested_ids:
            visit(analyzer_id, ())

        remaining = {key: set(value) for key, value in graph.items()}
        stages: list[ExecutionStage] = []
        resolved: list[str] = []

        while remaining:
            ready = tuple(sorted(key for key, deps in remaining.items() if not deps))
            if not ready:
                raise DependencyCycleError("Unable to resolve analyzer dependency graph")
            stages.append(ExecutionStage(ready))
            resolved.extend(ready)
            for analyzer_id in ready:
                remaining.pop(analyzer_id)
            for dependencies in remaining.values():
                dependencies.difference_update(ready)

        return AnalysisPlan(
            requested=requested_ids,
            resolved=tuple(resolved),
            stages=tuple(stages),
        )
