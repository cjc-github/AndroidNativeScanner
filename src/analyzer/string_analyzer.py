"""
字符串分析模块
负责从.so文件中提取字符串
"""

from pathlib import Path
from typing import List

from ..utils import run_cmd


def extract_strings(so_path: str) -> List[str]:
    """
    从.so文件中提取字符串
    
    Args:
        so_path: .so文件路径
        
    Returns:
        字符串列表
    """
    rc, str_out, str_err = run_cmd(["strings", so_path])
    
    if rc != 0:
        return []
    
    # 将strings输出按行保存以便后续多种检测复用
    strings_output = str_out.splitlines()
    return strings_output


def filter_strings_by_length(strings: List[str], min_length: int = 4) -> List[str]:
    """
    根据长度过滤字符串
    
    Args:
        strings: 字符串列表
        min_length: 最小长度
        
    Returns:
        过滤后的字符串列表
    """
    return [s for s in strings if len(s) >= min_length]


def get_string_summary(all_strings: List[str], filtered_strings: List[str]) -> dict:
    """
    获取字符串分析摘要
    
    Args:
        all_strings: 所有字符串列表
        filtered_strings: 过滤后的字符串列表
        
    Returns:
        包含字符串分析摘要的字典
    """
    summary = {}
    
    summary["total_strings"] = len(all_strings)
    summary["filtered_strings"] = len(filtered_strings)
    
    if filtered_strings:
        # 统计字符串长度分布
        length_distribution = {}
        for s in filtered_strings:
            length = len(s)
            if length not in length_distribution:
                length_distribution[length] = 0
            length_distribution[length] += 1
        
        summary["length_distribution"] = length_distribution
        summary["avg_length"] = sum(len(s) for s in filtered_strings) / len(filtered_strings)
        summary["max_length"] = max(len(s) for s in filtered_strings)
        summary["min_length"] = min(len(s) for s in filtered_strings)
    
    # 计算风险分数
    summary["risk_score"] = len(filtered_strings) // 100  # 每100个字符串加1分
    
    return summary