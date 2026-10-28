"""File-backed analyzer result cache."""

import hashlib
import json
from pathlib import Path

from ...infrastructure.config import RuntimeConfig
from ...infrastructure.serialization import to_primitive
from ..models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Diagnostic,
    DiagnosticLevel,
    Finding,
    Severity,
)
from ..models.result import RESULT_SCHEMA_VERSION

_CODE_VERSION: str | None = None


def code_version() -> str:
    """Fingerprint of the running code, stable within one code state.

    Every ``.py`` file of the package feeds the digest, so any source change
    (fix, edit, re-install) moves the fingerprint and invalidates cached
    results. Cached entries live in a per-version directory; entries from
    other versions become unreachable instead of silently reused.
    """
    global _CODE_VERSION
    if _CODE_VERSION is None:
        digest = hashlib.sha256()
        package_root = Path(__file__).resolve().parents[2]
        for path in sorted(package_root.rglob("*.py")):
            digest.update(str(path.relative_to(package_root)).encode("utf-8"))
            digest.update(path.read_bytes())
        _CODE_VERSION = digest.hexdigest()[:16]
    return _CODE_VERSION


def _reconstruct_finding(item: dict) -> Finding:
    return Finding(
        rule_id=item["rule_id"],
        title=item["title"],
        category=item["category"],
        severity=Severity(item["severity"]),
        confidence=Confidence(item["confidence"]),
        message=item["message"],
        fingerprint=item.get("fingerprint", ""),
        rule_version=item.get("rule_version", "1.0.0"),
        locations=tuple(item.get("locations", ())),
        evidence=tuple(item.get("evidence", ())),
        remediation=item.get("remediation"),
        references=tuple(item.get("references", ())),
    )


def _reconstruct_findings(items: list[dict]) -> list[Finding]:
    return [_reconstruct_finding(item) for item in items]


def _reconstruct_diagnostics(items: list[dict]) -> list[Diagnostic]:
    return [
        Diagnostic(
            code=item["code"],
            level=DiagnosticLevel(item["level"]),
            message=item["message"],
            analyzer_id=item.get("analyzer_id"),
            details=dict(item.get("details", {})),
        )
        for item in items
    ]


class RuntimeCache:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def _path(
        self, target: AnalysisTarget, analyzer_id: str, analyzer_version: str
    ) -> Path:
        safe_id = analyzer_id.replace(".", "_")
        return (
            self.config.cache_dir
            / code_version()
            / target.sha256
            / f"{safe_id}-{analyzer_version}.json"
        )

    def get(
        self, target: AnalysisTarget, analyzer_id: str, analyzer_version: str
    ) -> AnalysisResult | None:
        path = self._path(target, analyzer_id, analyzer_version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return AnalysisResult(
            analyzer_id=payload["analyzer_id"],
            analyzer_version=payload["analyzer_version"],
            status=AnalysisStatus(payload["status"]),
            data=payload.get("data", {}),
            findings=_reconstruct_findings(payload.get("findings", [])),
            diagnostics=_reconstruct_diagnostics(payload.get("diagnostics", [])),
            duration_ms=payload.get("duration_ms", 0),
            cache_hit=True,
            # Older cache files (written before ``text`` existed) have no such
            # key; the runtime reparses an empty text on load, so this stays a
            # cheap optional field rather than a cache-invalidating change.
            text=payload.get("text", ""),
            schema_version=payload.get("schema_version", RESULT_SCHEMA_VERSION),
        )

    def put(self, target: AnalysisTarget, result: AnalysisResult) -> None:
        path = self._path(target, result.analyzer_id, result.analyzer_version)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(to_primitive(result), ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        tmp.replace(path)
