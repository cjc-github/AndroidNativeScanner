"""Analysis target model."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AnalysisTarget:
    path: Path
    real_path: Path
    name: str
    size: int
    sha256: str
    file_type: str = "unknown"
