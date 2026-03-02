"""
敏感模式分析模块
检测 .so 文件字符串中的 API Key、Token、JWT 等敏感信息
"""

import re
from typing import Any, Dict, List, Tuple

from .base import BaseAnalyzer
from ..utils import extract_strings_from_so

SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "OpenAI Key": r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "JWT": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Password/Token": r"(?:pass(?:word)?|pwd|token|auth)[\"'=:\\s]+[^\"\\s]+",
}

_COMPILED = {k: re.compile(v) for k, v in SENSITIVE_PATTERNS.items()}


class SensitiveAnalyzer(BaseAnalyzer):
    name = "敏感模式检测"
    key = "sensitive_patterns"
    summary_key = "sensitive_summary"

    def analyze(self, so_file: str, **context) -> List[Tuple[str, str]]:
        strings = context.get("strings") or extract_strings_from_so(so_file)
        findings: List[Tuple[str, str]] = []
        for line in strings:
            for label, cre in _COMPILED.items():
                if cre.search(line):
                    findings.append((label, line.strip()))
        return findings

    def summarize(self, results: Any) -> Dict[str, Any]:
        findings: List[Tuple[str, str]] = results if isinstance(results, list) else []

        type_counts: Dict[str, int] = {}
        risk_score = 0
        for label, _ in findings:
            type_counts[label] = type_counts.get(label, 0) + 1
            if "Key" in label or "Token" in label:
                risk_score += 4
            elif "JWT" in label:
                risk_score += 3
            else:
                risk_score += 2

        return {
            "total_sensitive": len(findings),
            "type_counts": type_counts,
            "risk_score": risk_score,
        }
