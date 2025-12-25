"""
符号分析模块
负责分析.so文件的导出符号
"""

from typing import Dict, List

from ..utils import run_cmd

# 与远程命令执行 / 动态加载相关的关键词，用于在符号中查找可疑项
RCE_KEYWORDS = [
    'system', 'exec', 'sh', '/bin', 'chmod', 'su', 'curl', 'wget', 'eval',
    'Runtime', 'loadLibrary', 'popen', 'dlopen', 'dlsym', 'fopen', 'strcpy', 'sprintf'
]


def analyze_exported_symbols(so_path: str) -> List[str]:
    """
    分析导出符号
    
    Args:
        so_path: .so文件路径
        
    Returns:
        导出符号列表
    """
    rc, out, err = run_cmd(["nm", "-D", so_path])
    
    symbols = []
    
    if rc != 0:
        return symbols
    
    lines = out.splitlines()
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 3:
            symbol = parts[2]
            symbols.append(symbol)
    
    return symbols


def find_rce_symbols(symbols: List[str]) -> List[str]:
    """
    查找潜在的RCE相关符号
    
    Args:
        symbols: 符号列表
        
    Returns:
        RCE相关符号列表
    """
    rce_symbols = []
    
    for symbol in symbols:
        for keyword in RCE_KEYWORDS:
            if keyword.lower() in symbol.lower():
                rce_symbols.append(symbol)
                break
    
    return rce_symbols


def get_symbol_summary(exported_symbols: List[str], rce_symbols: List[str]) -> dict:
    """
    生成符号分析摘要
    
    Args:
        exported_symbols: 导出符号列表
        rce_symbols: RCE相关符号列表
        
    Returns:
        包含符号分析摘要的字典
    """
    summary = {
        "total_symbols": len(exported_symbols),
        "rce_symbols_count": len(rce_symbols),
        "rce_symbols": rce_symbols
    }
    
    # 计算风险分数
    risk_score = 0
    if rce_symbols:
        risk_score = min(30, len(rce_symbols) * 5)
    
    summary["risk_score"] = risk_score
    
    return summary