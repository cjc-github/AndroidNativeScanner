"""Framework diagnostic model."""

from dataclasses import dataclass, field
from typing import Any

from .status import DiagnosticLevel


@dataclass(frozen=True)
class Diagnostic:
    code: str
    level: DiagnosticLevel
    message: str
    analyzer_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
