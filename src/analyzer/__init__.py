"""
Android Native Scanner - 分析器模块
每个分析步骤都独立在一个文件中，便于维护和扩展
"""

# 导入所有分析模块
from .elf_analyzer import analyze_elf_header, get_elf_header_summary
from .symbol_analyzer import analyze_exported_symbols, find_rce_symbols, get_symbol_summary
from .string_analyzer import extract_strings, filter_strings_by_length, get_string_summary
from .sensitive_analyzer import analyze_sensitive_patterns, get_sensitive_summary
from .url_analyzer import analyze_urls, get_url_summary
from .base64_analyzer import analyze_base64, get_base64_summary
from .jni_analyzer import analyze_jni_symbols, get_jni_summary
from .analysis_coordinator import analyze_so_file, get_analysis_summary

# 导出主要接口
__all__ = [
    # ELF头分析
    "analyze_elf_header",
    "get_elf_header_summary",
    
    # 符号分析
    "analyze_exported_symbols",
    "find_rce_symbols",
    "get_symbol_summary",
    
    # 字符串分析
    "extract_strings",
    "filter_strings_by_length",
    "get_string_summary",
    
    # 敏感模式分析
    "analyze_sensitive_patterns",
    "get_sensitive_summary",
    
    # URL分析
    "analyze_urls",
    "get_url_summary",
    
    # Base64分析
    "analyze_base64",
    "get_base64_summary",
    
    # JNI分析
    "analyze_jni_symbols",
    "get_jni_summary",
    
    # 主协调器
    "analyze_so_file",
    "get_analysis_summary"
]