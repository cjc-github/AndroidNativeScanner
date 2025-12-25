"""
分析协调器模块
负责协调所有分析模块的执行和结果汇总
"""

import os
from typing import Dict, Any

from .elf_analyzer import analyze_elf_header, get_elf_header_summary
from .symbol_analyzer import analyze_exported_symbols, find_rce_symbols, get_symbol_summary
from .string_analyzer import extract_strings, filter_strings_by_length, get_string_summary
from .sensitive_analyzer import analyze_sensitive_patterns, get_sensitive_summary
from .url_analyzer import analyze_urls, get_url_summary
from .base64_analyzer import analyze_base64, get_base64_summary
from .jni_analyzer import analyze_jni_symbols, get_jni_summary


def analyze_so_file(so_file: str) -> Dict[str, Any]:
    """
    协调分析.so文件
    
    Args:
        so_file: .so文件路径
        
    Returns:
        包含所有分析结果的字典
    """
    if not os.path.exists(so_file):
        raise FileNotFoundError(f"文件不存在: {so_file}")
    
    results = {}
    
    # 1. ELF头分析
    print("🔍 分析ELF头信息...")
    elf_header = analyze_elf_header(so_file)
    results["elf_header"] = elf_header
    
    # 2. 符号分析
    print("🔍 分析导出符号...")
    exported_symbols = analyze_exported_symbols(so_file)
    rce_symbols = find_rce_symbols(exported_symbols)
    results["symbols"] = {
        "exported": exported_symbols,
        "rce": rce_symbols
    }
    
    # 3. 字符串分析
    print("🔍 提取字符串...")
    all_strings = extract_strings(so_file)
    filtered_strings = filter_strings_by_length(all_strings)
    results["strings"] = {
        "all": all_strings,
        "filtered": filtered_strings
    }
    
    # 4. 敏感模式分析
    print("🔍 检测敏感模式...")
    sensitive_patterns = analyze_sensitive_patterns(filtered_strings)
    results["sensitive_patterns"] = sensitive_patterns
    
    # 5. URL分析
    print("🔍 检测URL...")
    urls = analyze_urls(filtered_strings)
    results["urls"] = urls
    
    # 6. Base64分析
    print("🔍 检测Base64编码...")
    base64_strings = analyze_base64(filtered_strings)
    results["base64"] = base64_strings
    
    # 7. JNI分析
    print("🔍 分析JNI符号...")
    jni_symbols = analyze_jni_symbols(so_file)
    results["jni"] = jni_symbols
    
    return results


def get_analysis_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    生成分析摘要
    
    Args:
        results: 分析结果字典
        
    Returns:
        包含所有分析摘要的字典
    """
    summary = {}
    
    # 各模块摘要
    summary["elf_summary"] = get_elf_header_summary(results["elf_header"])
    summary["symbol_summary"] = get_symbol_summary(results["symbols"]["exported"], results["symbols"]["rce"])
    summary["string_summary"] = get_string_summary(results["strings"]["all"], results["strings"]["filtered"])
    summary["sensitive_summary"] = get_sensitive_summary(results["sensitive_patterns"])
    summary["url_summary"] = get_url_summary(results["urls"])
    summary["base64_summary"] = get_base64_summary(results["base64"])
    summary["jni_summary"] = get_jni_summary(results["jni"])
    
    # 总体风险评分
    total_risk_score = (
        summary["elf_summary"]["risk_score"] +
        summary["symbol_summary"]["risk_score"] +
        summary["string_summary"]["risk_score"] +
        summary["sensitive_summary"]["risk_score"] +
        summary["url_summary"]["risk_score"] +
        summary["base64_summary"]["risk_score"] +
        summary["jni_summary"]["risk_score"]
    )
    
    summary["total_risk_score"] = total_risk_score
    
    # 风险等级评估
    if total_risk_score >= 50:
        summary["risk_level"] = "HIGH"
    elif total_risk_score >= 20:
        summary["risk_level"] = "MEDIUM"
    else:
        summary["risk_level"] = "LOW"
    
    return summary