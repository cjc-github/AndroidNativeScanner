"""
URL分析模块
负责检测字符串中的硬编码URL
"""

from typing import List

from ..scanners import scan_urls


def analyze_urls(strings: List[str]) -> List[str]:
    """
    分析硬编码URL
    
    Args:
        strings: 字符串列表
        
    Returns:
        URL列表
    """
    return scan_urls(strings)


def get_url_summary(urls: List[str]) -> dict:
    """
    获取URL分析摘要
    
    Args:
        urls: URL列表
        
    Returns:
        包含URL分析摘要的字典
    """
    summary = {}
    
    summary["total_urls"] = len(urls)
    
    # 按域名分类统计
    domain_counts = {}
    for url in urls:
        # 简单的域名提取
        if "://" in url:
            domain = url.split("://")[1].split("/")[0]
        else:
            domain = url.split("/")[0]
        
        if domain not in domain_counts:
            domain_counts[domain] = 0
        domain_counts[domain] += 1
    
    summary["domain_counts"] = domain_counts
    
    # 计算风险分数
    summary["risk_score"] = len(urls) * 2
    
    return summary