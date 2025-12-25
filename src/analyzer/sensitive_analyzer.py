"""
敏感模式分析模块
负责检测字符串中的敏感数据模式
"""

from typing import List, Tuple

from ..scanners import scan_sensitive_patterns


def analyze_sensitive_patterns(strings: List[str]) -> List[Tuple[str, str]]:
    """
    分析敏感数据模式
    
    Args:
        strings: 字符串列表
        
    Returns:
        敏感模式检测结果列表 (标签, 匹配内容)
    """
    return scan_sensitive_patterns(strings)


def get_sensitive_summary(sensitive_patterns: List[Tuple[str, str]]) -> dict:
    """
    获取敏感模式分析摘要
    
    Args:
        sensitive_patterns: 敏感模式检测结果
        
    Returns:
        包含敏感模式分析摘要的字典
    """
    summary = {}
    
    summary["total_sensitive"] = len(sensitive_patterns)
    
    # 按类型统计
    type_counts = {}
    for label, _ in sensitive_patterns:
        if label not in type_counts:
            type_counts[label] = 0
        type_counts[label] += 1
    
    summary["type_counts"] = type_counts
    
    # 计算风险分数
    risk_score = 0
    for label, _ in sensitive_patterns:
        if "Key" in label or "Token" in label:
            risk_score += 4
        elif "JWT" in label:
            risk_score += 3
        else:
            risk_score += 2
    
    summary["risk_score"] = risk_score
    
    return summary