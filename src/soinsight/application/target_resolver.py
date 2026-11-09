"""Resolve and validate local analysis targets."""

from fnmatch import fnmatch
from hashlib import sha256
from os import walk
from pathlib import Path

from ..core.models import AnalysisTarget


class TargetResolutionError(ValueError):
    pass


#: Directories that are never worth scanning: version-control metadata,
#: virtual environments and build caches hold no library the user cares about.
DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {".git", ".venv", "venv", "__pycache__", ".soinsight", "node_modules", ".tox"}
)


class TargetResolver:
    def resolve(self, path: Path) -> AnalysisTarget:
        candidate = path.expanduser()
        if not candidate.exists():
            raise TargetResolutionError(f"Target does not exist: {candidate}")
        if not candidate.is_file():
            raise TargetResolutionError(
                f"Framework scan currently expects a single file: {candidate}"
            )
        return self._describe(candidate)

    def resolve_many(
        self,
        paths,
        *,
        include: tuple[str, ...] = (),
        exclude: tuple[str, ...] = (),
    ) -> list[AnalysisTarget]:
        """Resolve files and directories into a de-duplicated target list.

        A directory is expanded recursively. ``include`` keeps only the files
        whose name or relative path matches one of its glob patterns; when it
        is empty every file is kept. ``exclude`` drops the files that match
        one of its patterns. Both are matched against the file name *and*
        against the path relative to the scanned root, so ``*.so`` and
        ``libs/*.so`` both work.

        Symbolic links are not followed out of the scanned tree, and the same
        file reached through two paths is reported once.
        """
        candidates: list[Path] = []
        for raw in paths or ():
            candidate = Path(raw).expanduser()
            if not candidate.exists():
                raise TargetResolutionError(f"Target does not exist: {candidate}")
            if candidate.is_dir():
                candidates.extend(
                    self._expand_directory(candidate, include=include, exclude=exclude)
                )
            elif self._matches(candidate.name, include, default=True) and not self._matches(
                candidate, exclude, default=False
            ):
                candidates.append(candidate)

        targets: list[AnalysisTarget] = []
        seen: set[Path] = set()
        for candidate in sorted(set(candidates)):
            real = candidate.resolve()
            if real in seen:
                continue
            seen.add(real)
            targets.append(self._describe(candidate))
        if not targets:
            raise TargetResolutionError(
                "No target files matched the selection; check the path and the "
                "--include/--exclude filters."
            )
        return targets

    def _describe(self, candidate: Path) -> AnalysisTarget:
        """Hash and describe one file."""
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

    def _expand_directory(
        self,
        root: Path,
        *,
        include: tuple[str, ...] = (),
        exclude: tuple[str, ...] = (),
    ) -> list[Path]:
        """Every file under ``root`` that survives the filters."""
        resolved_root = root.resolve()
        collected: list[Path] = []
        for current, directories, files in walk(resolved_root, followlinks=False):
            directories[:] = [
                name
                for name in directories
                if name not in DEFAULT_EXCLUDED_DIRECTORIES
            ]
            current_path = Path(current)
            for name in files:
                path = current_path / name
                try:
                    real = path.resolve()
                except OSError:
                    continue
                # A symbolic link that points outside the tree is not part of
                # the selection: following it would analyze a different file.
                if not self._within(real, resolved_root):
                    continue
                relative = path.relative_to(resolved_root).as_posix()
                if not self._matches(relative, include, default=True):
                    continue
                if self._matches(relative, exclude, default=False):
                    continue
                if self._matches(path, exclude, default=False):
                    continue
                collected.append(path)
        return collected

    @staticmethod
    def _within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _matches(value, patterns: tuple[str, ...], *, default: bool) -> bool:
        """Whether ``value`` matches any glob pattern.

        ``default`` is the answer when no pattern is given, so an empty
        ``include`` keeps everything and an empty ``exclude`` drops nothing.
        """
        if not patterns:
            return default
        text = str(value)
        name = Path(text).name
        for pattern in patterns:
            if fnmatch(name, pattern) or fnmatch(text, pattern):
                return True
        return False
