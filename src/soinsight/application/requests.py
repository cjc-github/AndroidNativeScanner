"""Application request models."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AnalysisRequest:
    target: Path
    analyzer_ids: tuple[str, ...]
    profile: str | None = None
    baseline: Path | None = None
    """Baseline of accepted findings; matches are marked suppressed."""
    update_baseline: Path | None = None
    """Write the current non-suppressed findings as the new baseline."""
    fail_on: str | None = None
    """Severity threshold that fails the run (CI gate)."""
