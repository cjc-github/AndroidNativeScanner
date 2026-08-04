"""Runtime configuration model."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RuntimeConfig:
    jobs: int = 1
    timeout_seconds: int = 60
    quiet: bool = False
    verbose: bool = False
    no_color: bool = False
    cache_enabled: bool = True
    cache_dir: Path = Path(".soinsight/cache")
    fail_fast: bool = False
    extra: dict[str, object] = field(default_factory=dict)
