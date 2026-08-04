"""Shared runtime context passed to analyzers."""

from dataclasses import dataclass, field
from threading import Event, Lock
from typing import Any

from ..models import AnalysisResult, AnalysisTarget, Diagnostic, Finding


class CancellationToken:
    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


@dataclass
class AnalysisContext:
    run_id: str
    target: AnalysisTarget
    config: Any
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    _findings: list[Finding] = field(default_factory=list, repr=False)
    _results: dict[str, AnalysisResult] = field(default_factory=dict, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    @property
    def findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    def add_findings(self, findings: list[Finding]) -> None:
        with self._lock:
            self._findings.extend(findings)

    @property
    def results(self) -> dict[str, AnalysisResult]:
        with self._lock:
            return dict(self._results)

    def add_result(self, result: AnalysisResult) -> None:
        with self._lock:
            self._results[result.analyzer_id] = result

    def require(self, analyzer_id: str) -> AnalysisResult:
        with self._lock:
            try:
                return self._results[analyzer_id]
            except KeyError as exc:
                raise KeyError(f"Required analyzer result is missing: {analyzer_id}") from exc

    def optional(self, analyzer_id: str) -> AnalysisResult | None:
        with self._lock:
            return self._results.get(analyzer_id)
