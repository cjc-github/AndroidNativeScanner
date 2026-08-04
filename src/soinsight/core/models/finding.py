"""Normalized security finding model."""

from dataclasses import dataclass, field
from typing import Any

from .status import Confidence, Severity


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    message: str
    fingerprint: str = ""
    rule_version: str = "1.0.0"
    locations: tuple[dict[str, Any], ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    remediation: str | None = None
    references: tuple[dict[str, str], ...] = ()
