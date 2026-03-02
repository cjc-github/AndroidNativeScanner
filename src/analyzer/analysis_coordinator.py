"""
分析协调器模块
通过 BaseAnalyzer 统一接口调度所有分析器，汇总结果与风险评分
"""

import os
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer
from .elf_analyzer import ElfAnalyzer
from .symbol_analyzer import SymbolAnalyzer
from .string_analyzer import StringAnalyzer
from .sensitive_analyzer import SensitiveAnalyzer
from .url_analyzer import UrlAnalyzer
from .base64_analyzer import Base64Analyzer
from .jni_analyzer import JniAnalyzer


class AnalysisCoordinator:
    """协调所有分析器的执行顺序，共享上下文以优化性能"""

    def __init__(self) -> None:
        self.analyzers: List[BaseAnalyzer] = [
            ElfAnalyzer(),
            SymbolAnalyzer(),
            StringAnalyzer(),
            SensitiveAnalyzer(),
            UrlAnalyzer(),
            Base64Analyzer(),
            JniAnalyzer(),
        ]

    def analyze(self, so_file: str) -> Dict[str, Any]:
        if not os.path.exists(so_file):
            raise FileNotFoundError(f"文件不存在: {so_file}")

        results: Dict[str, Any] = {}
        shared_strings: Optional[List[str]] = None

        for analyzer in self.analyzers:
            print(f"🔍 {analyzer.name}...")
            context: Dict[str, Any] = {}
            if shared_strings is not None:
                context["strings"] = shared_strings

            result = analyzer.analyze(so_file, **context)
            results[analyzer.key] = result

            if analyzer.key == "strings":
                shared_strings = result.get("filtered", [])

        return results

    def summarize(self, results: Dict[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        total_risk = 0

        for analyzer in self.analyzers:
            s = analyzer.summarize(results.get(analyzer.key, {}))
            summary[analyzer.summary_key] = s
            total_risk += s.get("risk_score", 0)

        summary["total_risk_score"] = total_risk

        if total_risk >= 60:
            summary["risk_level"] = "CRITICAL"
        elif total_risk >= 40:
            summary["risk_level"] = "HIGH"
        elif total_risk >= 20:
            summary["risk_level"] = "MEDIUM"
        else:
            summary["risk_level"] = "LOW"

        return summary


_coordinator = AnalysisCoordinator()


def analyze_so_file(so_file: str) -> Dict[str, Any]:
    """模块级快捷函数：分析 .so 文件"""
    return _coordinator.analyze(so_file)


def get_analysis_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """模块级快捷函数：生成分析摘要"""
    return _coordinator.summarize(results)
