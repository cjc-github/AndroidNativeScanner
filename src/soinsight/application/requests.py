"""Application request models."""

from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class BatchRequest:
    """One analysis request that covers several targets.

    A directory in ``targets`` is expanded by the target resolver; the
    ``include`` and ``exclude`` globs narrow that expansion. The baseline and
    gate fields behave as they do for a single target, except that
    ``update_baseline`` collects the accepted findings of *every* target into
    one baseline instead of letting the last target overwrite the others.
    """

    targets: tuple[Path, ...]
    analyzer_ids: tuple[str, ...]
    profile: str | None = None
    baseline: Path | None = None
    update_baseline: Path | None = None
    fail_on: str | None = None
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()

    def as_single(self, target: Path) -> AnalysisRequest:
        """The equivalent single-target request."""
        return AnalysisRequest(
            target=target,
            analyzer_ids=self.analyzer_ids,
            profile=self.profile,
            baseline=self.baseline,
            update_baseline=None,
            fail_on=self.fail_on,
        )
