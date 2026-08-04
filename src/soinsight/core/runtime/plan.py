"""Execution plan models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionStage:
    analyzer_ids: tuple[str, ...]


@dataclass(frozen=True)
class AnalysisPlan:
    requested: tuple[str, ...]
    resolved: tuple[str, ...]
    stages: tuple[ExecutionStage, ...]
