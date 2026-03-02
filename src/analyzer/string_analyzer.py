"""
字符串分析模块
从 .so 文件中提取字符串并做统计分析
"""

from typing import Any, Dict, List

from .base import BaseAnalyzer
from ..utils import run_cmd


class StringAnalyzer(BaseAnalyzer):
    name = "字符串分析"
    key = "strings"
    summary_key = "string_summary"

    def analyze(self, so_file: str, **context) -> Dict[str, Any]:
        rc, out, _ = run_cmd(["strings", so_file])
        all_strings = out.splitlines() if rc == 0 else []
        filtered = [s for s in all_strings if len(s) >= 4]
        return {"all": all_strings, "filtered": filtered}

    def summarize(self, results: Any) -> Dict[str, Any]:
        all_strings: List[str] = results.get("all", [])
        filtered: List[str] = results.get("filtered", [])

        summary: Dict[str, Any] = {
            "total_strings": len(all_strings),
            "filtered_strings": len(filtered),
            "risk_score": len(filtered) // 100,
        }

        if filtered:
            summary["avg_length"] = sum(len(s) for s in filtered) / len(filtered)
            summary["max_length"] = max(len(s) for s in filtered)
            summary["min_length"] = min(len(s) for s in filtered)

        return summary
