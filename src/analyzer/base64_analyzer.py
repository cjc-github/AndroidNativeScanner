"""
Base64分析模块
负责检测字符串中的Base64编码数据
"""

from typing import List

from ..scanners import detect_base64_strings


def analyze_base64(strings: List[str]) -> List[str]:
    """
    分析Base64编码数据
    
    Args:
        strings: 字符串列表
        
    Returns:
        Base64字符串列表
    """
    base64_results = detect_base64_strings(strings)
    return [result[0] for result in base64_results]  # 只返回原始Base64字符串


def get_base64_summary(base64_strings: List[str]) -> dict:
    """
    获取Base64分析摘要
    
    Args:
        base64_strings: Base64字符串列表
        
    Returns:
        包含Base64分析摘要的字典
    """
    summary = {}
    
    summary["total_base64"] = len(base64_strings)
    
    # 按长度分类统计
    length_counts = {}
    for base64_str in base64_strings:
        length = len(base64_str)
        if length not in length_counts:
            length_counts[length] = 0
        length_counts[length] += 1
    
    summary["length_counts"] = length_counts
    
    # 计算风险分数
    summary["risk_score"] = len(base64_strings) * 3
    
    return summary