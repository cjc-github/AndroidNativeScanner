"""Analyzer registration and lookup."""

from collections.abc import Iterable

from .base import Analyzer
from .metadata import AnalyzerMetadata


class AnalyzerRegistryError(ValueError):
    pass


class AnalyzerNotFoundError(AnalyzerRegistryError):
    pass


class AnalyzerRegistry:
    def __init__(self) -> None:
        self._analyzers: dict[str, Analyzer] = {}

    def register(self, analyzer: Analyzer) -> None:
        analyzer_id = analyzer.metadata.id
        if not analyzer_id:
            raise AnalyzerRegistryError("Analyzer id cannot be empty")
        if analyzer_id in self._analyzers:
            raise AnalyzerRegistryError(f"Analyzer already registered: {analyzer_id}")
        self._analyzers[analyzer_id] = analyzer

    def register_many(self, analyzers: Iterable[Analyzer]) -> None:
        for analyzer in analyzers:
            self.register(analyzer)

    def get(self, analyzer_id: str) -> Analyzer:
        try:
            return self._analyzers[analyzer_id]
        except KeyError as exc:
            raise AnalyzerNotFoundError(f"Analyzer not found: {analyzer_id}") from exc

    def contains(self, analyzer_id: str) -> bool:
        return analyzer_id in self._analyzers

    def list(self) -> list[AnalyzerMetadata]:
        return [self._analyzers[key].metadata for key in sorted(self._analyzers)]

    def default_ids(self) -> tuple[str, ...]:
        return tuple(
            metadata.id for metadata in self.list() if metadata.default_enabled
        )
