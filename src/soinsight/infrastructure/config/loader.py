"""Build validated runtime settings from already-resolved configuration values.

YAML persistence and selection are handled by :class:`YamlConfigStore`; the CLI
applies precedence and passes the resolved values through this boundary.
"""

from pathlib import Path

from .settings import RuntimeConfig


class ConfigLoader:
    def load(
        self,
        *,
        jobs: int | None = None,
        timeout_seconds: int | None = None,
        quiet: bool = False,
        verbose: bool = False,
        no_color: bool = False,
        cache_enabled: bool = True,
        cache_dir: str | Path | None = None,
        fail_fast: bool = False,
        extra: dict[str, object] | None = None,
    ) -> RuntimeConfig:
        resolved_jobs = jobs if jobs is not None else 1
        resolved_timeout = timeout_seconds if timeout_seconds is not None else 60
        if resolved_jobs < 1:
            raise ValueError("jobs must be at least 1")
        if resolved_timeout < 1:
            raise ValueError("timeout must be at least 1 second")
        return RuntimeConfig(
            jobs=resolved_jobs,
            timeout_seconds=resolved_timeout,
            quiet=quiet,
            verbose=verbose,
            no_color=no_color,
            cache_enabled=cache_enabled,
            cache_dir=Path(cache_dir) if cache_dir else Path(".soinsight/cache"),
            fail_fast=fail_fast,
            extra=dict(extra or {}),
        )
