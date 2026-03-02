"""
Base64 分析模块
检测 .so 文件字符串中的 Base64 编码数据
"""

import base64
import re
from typing import Any, Dict, List

from .base import BaseAnalyzer
from ..utils import extract_strings_from_so

_BASE64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
_BASE64_MAX_BYTES = 4096


class Base64Analyzer(BaseAnalyzer):
    name = "Base64检测"
    key = "base64"
    summary_key = "base64_summary"

    def analyze(self, so_file: str, **context) -> List[str]:
        strings = context.get("strings") or extract_strings_from_so(so_file)
        found: List[str] = []
        for s in strings:
            if not _BASE64_CANDIDATE.match(s) or len(s) > _BASE64_MAX_BYTES:
                continue
            try:
                decoded_bytes = base64.b64decode(s, validate=True)
                decoded = decoded_bytes.decode("utf-8", errors="strict")
                if sum(1 for c in decoded if c.isprintable()) / max(1, len(decoded)) > 0.6:
                    found.append(s)
            except Exception:
                continue
        return found

    def summarize(self, results: Any) -> Dict[str, Any]:
        items: List[str] = results if isinstance(results, list) else []
        return {
            "total_base64": len(items),
            "risk_score": len(items) * 3,
        }
