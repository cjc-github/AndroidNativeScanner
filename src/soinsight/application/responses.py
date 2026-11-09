"""Application response model."""

from dataclasses import dataclass, field

from ..core.models import Diagnostic, ScanResult


@dataclass
class ApplicationResponse:
    result: ScanResult | None
    diagnostics: list[Diagnostic] = field(default_factory=list)
    exit_code: int = 0


@dataclass
class BatchResponse:
    """The outcome of a multi-target run.

    ``results`` is keyed by the resolved path of each target, so a caller can
    tell which file produced which document. ``failed`` lists the targets
    that did not complete, and ``exit_code`` carries the worst outcome of the
    batch (0 when every target succeeded).
    """

    results: dict[str, ScanResult] = field(default_factory=dict)
    failed: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    exit_code: int = 0
    target_count: int = 0

    @property
    def findings(self) -> list:
        """Every finding of every target, in target order."""
        collected = []
        for result in self.results.values():
            collected.extend(result.findings)
        return collected

    def summary(self) -> dict:
        return {
            "target_count": self.target_count,
            "completed_count": len(self.results),
            "failed_count": len(self.failed),
            "failed": list(self.failed),
            "finding_count": len(self.findings),
            "exit_code": self.exit_code,
        }
