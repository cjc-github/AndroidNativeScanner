"""Application request models."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AnalysisRequest:
    target: Path
    analyzer_ids: tuple[str, ...]
    profile: str | None = None
