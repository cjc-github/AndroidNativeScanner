"""
ELF 头分析模块
通过 readelf 解析 .so 文件的 ELF 头信息
"""

from typing import Any, Dict

from .base import BaseAnalyzer
from ..utils import run_cmd


class ElfAnalyzer(BaseAnalyzer):
    name = "ELF头分析"
    key = "elf_header"
    summary_key = "elf_summary"

    def analyze(self, so_file: str, **context) -> Dict[str, Any]:
        rc, out, _ = run_cmd(["readelf", "-h", so_file])

        result: Dict[str, Any] = {}
        if rc != 0:
            result["risk_score"] = 0
            return result

        field_map = {
            "Type:": "type",
            "Machine:": "machine",
            "Entry point address:": "entry_point",
            "Number of program headers:": "program_headers",
            "Number of section headers:": "section_headers",
        }

        for line in out.splitlines():
            line = line.strip()
            for prefix, field in field_map.items():
                if prefix in line:
                    result[field] = line.split(prefix)[1].strip()

        result["risk_score"] = 0
        return result

    def summarize(self, results: Any) -> Dict[str, Any]:
        return results
