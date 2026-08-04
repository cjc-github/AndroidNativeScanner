"""Normalized analyzer and scan result models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .diagnostic import Diagnostic
from .finding import Finding
from .status import AnalysisStatus
from .target import AnalysisTarget

RESULT_SCHEMA_VERSION = "soinsight.result/v1"
SCAN_SCHEMA_VERSION = "soinsight.scan/v1"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AnalysisResult:
    analyzer_id: str
    analyzer_version: str
    status: AnalysisStatus
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    duration_ms: int = 0
    cache_hit: bool = False
    schema_version: str = RESULT_SCHEMA_VERSION


@dataclass
class ScanResult:
    target: AnalysisTarget
    status: AnalysisStatus
    results: dict[str, AnalysisResult] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    requested_analyzers: tuple[str, ...] = ()
    resolved_analyzers: tuple[str, ...] = ()
    profile: str | None = None
    started_at: str = field(default_factory=utc_now_iso)
    duration_ms: int = 0
    schema_version: str = SCAN_SCHEMA_VERSION
    tool_version: str = ""
