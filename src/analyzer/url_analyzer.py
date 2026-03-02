"""
URL 分析模块
检测 .so 文件字符串中的硬编码 URL
"""

import re
from typing import Any, Dict, List

from .base import BaseAnalyzer
from ..utils import extract_strings_from_so

_URL_RE = re.compile(r"https?://[^\s\"']+")


class UrlAnalyzer(BaseAnalyzer):
    name = "URL检测"
    key = "urls"
    summary_key = "url_summary"

    def analyze(self, so_file: str, **context) -> List[str]:
        strings = context.get("strings") or extract_strings_from_so(so_file)
        urls: List[str] = []
        for s in strings:
            m = _URL_RE.search(s)
            if m:
                urls.append(m.group(0))
        return urls

    def summarize(self, results: Any) -> Dict[str, Any]:
        urls: List[str] = results if isinstance(results, list) else []

        domain_counts: Dict[str, int] = {}
        for url in urls:
            domain = url.split("://")[1].split("/")[0] if "://" in url else url.split("/")[0]
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

        return {
            "total_urls": len(urls),
            "domain_counts": domain_counts,
            "risk_score": len(urls) * 2,
        }
