"""
符号分析模块
分析 .so 文件的导出符号，检测潜在的 RCE 相关危险函数
"""

from typing import Any, Dict, List

from .base import BaseAnalyzer
from ..utils import run_cmd

RCE_KEYWORDS = [
    "system", "exec", "sh", "/bin", "chmod", "su", "curl", "wget", "eval",
    "Runtime", "loadLibrary", "popen", "dlopen", "dlsym", "fopen", "strcpy", "sprintf",
]


class SymbolAnalyzer(BaseAnalyzer):
    name = "符号分析"
    key = "symbols"
    summary_key = "symbol_summary"

    def analyze(self, so_file: str, **context) -> Dict[str, Any]:
        rc, out, _ = run_cmd(["nm", "-D", so_file])

        exported: List[str] = []
        if rc == 0:
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    exported.append(parts[2])

        rce = [
            sym for sym in exported
            if any(kw.lower() in sym.lower() for kw in RCE_KEYWORDS)
        ]

        return {"exported": exported, "rce": rce}

    def summarize(self, results: Any) -> Dict[str, Any]:
        exported = results.get("exported", [])
        rce = results.get("rce", [])
        return {
            "total_symbols": len(exported),
            "rce_symbols_count": len(rce),
            "rce_symbols": rce,
            "risk_score": min(30, len(rce) * 5),
        }
