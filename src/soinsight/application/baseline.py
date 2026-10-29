"""Baseline suppression and the CI gate.

A baseline records the findings a team has already accepted, keyed by the
finding fingerprint, so a later scan can tell "known" from "new". Suppressed
findings stay in the result -- marked ``suppressed`` -- instead of disappearing:
hiding them would make the report lie about what the binary contains.

The gate turns the result into a build decision: it fails when any
non-suppressed finding reaches a configured severity. Both pieces are
deliberately small and file-based so CI can use them without extra services.
"""

import json
from dataclasses import dataclass, replace
from pathlib import Path

from ..core.models import Finding, Severity

__all__ = [
    "Baseline",
    "BaselineError",
    "SEVERITY_ORDER",
    "apply_baseline",
    "gate_failure",
    "load_baseline",
    "parse_threshold",
    "save_baseline",
]

BASELINE_VERSION = 1

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class BaselineError(ValueError):
    """The baseline file is unreadable or malformed."""


@dataclass(frozen=True)
class Baseline:
    """Accepted finding fingerprints."""

    fingerprints: frozenset[str]

    def __len__(self) -> int:
        return len(self.fingerprints)


def _finding_key(finding: Finding) -> str:
    """Suppression key: the fingerprint, falling back to rule + title."""
    return finding.fingerprint or f"{finding.rule_id}:{finding.title}"


def load_baseline(path: Path | str) -> Baseline:
    """Read a baseline file; a missing or malformed file is an error."""
    location = Path(path)
    try:
        payload = json.loads(location.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"Cannot read baseline '{location}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"Baseline '{location}' is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise BaselineError(f"Baseline '{location}' must be a JSON object")
    version = payload.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"Baseline '{location}' has unsupported version {version!r} "
            f"(expected {BASELINE_VERSION})"
        )
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(
        isinstance(item, str) for item in fingerprints
    ):
        raise BaselineError(
            f"Baseline '{location}' must carry a 'fingerprints' string array"
        )
    return Baseline(fingerprints=frozenset(fingerprints))


def save_baseline(path: Path | str, findings: list[Finding]) -> None:
    """Write the fingerprints of the given findings as a baseline."""
    location = Path(path)
    payload = {
        "version": BASELINE_VERSION,
        "fingerprints": sorted({_finding_key(finding) for finding in findings}),
    }
    location.parent.mkdir(parents=True, exist_ok=True)
    temporary = location.with_suffix(location.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(location)


def apply_baseline(findings: list[Finding], baseline: Baseline) -> list[Finding]:
    """Mark the findings the baseline accepts as suppressed."""
    return [
        replace(finding, suppressed=True)
        if _finding_key(finding) in baseline.fingerprints
        else finding
        for finding in findings
    ]


def parse_threshold(value: str) -> Severity:
    """Parse a gate threshold name into a severity."""
    try:
        return Severity(value.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(severity.value for severity in Severity)
        raise BaselineError(
            f"Unknown severity '{value}' for the gate (expected one of: {allowed})"
        ) from exc


def gate_failure(findings: list[Finding], threshold: Severity) -> Finding | None:
    """Return the worst non-suppressed finding at or above ``threshold``."""
    limit = SEVERITY_ORDER[threshold]
    candidates = [
        finding
        for finding in findings
        if not finding.suppressed and SEVERITY_ORDER[finding.severity] >= limit
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda finding: SEVERITY_ORDER[finding.severity])
