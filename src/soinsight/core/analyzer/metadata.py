"""Analyzer metadata and categories."""

from dataclasses import dataclass
from enum import Enum


class AnalyzerKind(str, Enum):
    COLLECTOR = "collector"
    TRANSFORMER = "transformer"
    DETECTOR = "detector"
    ASSISTANT = "assistant"


@dataclass(frozen=True)
class AnalyzerMetadata:
    id: str
    name: str
    version: str
    description: str = ""
    api_version: int = 1
    kind: AnalyzerKind = AnalyzerKind.COLLECTOR
    requires: tuple[str, ...] = ()
    optional_requires: tuple[str, ...] = ()
    default_enabled: bool = True
    cacheable: bool = True
    timeout_seconds: int = 60
