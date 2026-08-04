"""Resolve and validate local analysis targets."""

from hashlib import sha256
from pathlib import Path

from ..core.models import AnalysisTarget


class TargetResolutionError(ValueError):
    pass


class TargetResolver:
    def resolve(self, path: Path) -> AnalysisTarget:
        candidate = path.expanduser()
        if not candidate.exists():
            raise TargetResolutionError(f"Target does not exist: {candidate}")
        if not candidate.is_file():
            raise TargetResolutionError(
                f"Framework scan currently expects a single file: {candidate}"
            )
        real_path = candidate.resolve()
        digest = sha256()
        with real_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return AnalysisTarget(
            path=candidate,
            real_path=real_path,
            name=candidate.name,
            size=real_path.stat().st_size,
            sha256=digest.hexdigest(),
        )
