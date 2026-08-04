"""Application response model."""

from dataclasses import dataclass, field

from ..core.models import Diagnostic, ScanResult


@dataclass
class ApplicationResponse:
    result: ScanResult | None
    diagnostics: list[Diagnostic] = field(default_factory=list)
    exit_code: int = 0
