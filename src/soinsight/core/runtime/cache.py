"""File-backed analyzer result cache."""

import json

from ...infrastructure.config import RuntimeConfig
from ...infrastructure.serialization import to_primitive
from ..models import AnalysisResult, AnalysisStatus, AnalysisTarget
from ..models.result import RESULT_SCHEMA_VERSION


class RuntimeCache:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def _path(
        self, target: AnalysisTarget, analyzer_id: str, analyzer_version: str
    ) -> str:
        safe_id = analyzer_id.replace(".", "_")
        return self.config.cache_dir / target.sha256 / f"{safe_id}-{analyzer_version}.json"

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
            findings=payload.get("findings", []),
            diagnostics=payload.get("diagnostics", []),
            duration_ms=payload.get("duration_ms", 0),
            cache_hit=True,
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
