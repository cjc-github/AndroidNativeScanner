"""
JNI方法分析模块
负责检测JNI相关符号和方法
"""

from typing import List, Dict

from ..utils import run_cmd

# JNI相关关键词，用于在符号中查找JNI相关符号
JNI_KEYWORDS = [
    'jni', 'Java', 'JNI_', 'RegisterNatives', 'GetMethodID', 'GetFieldID',
    'CallVoidMethod', 'CallObjectMethod', 'CallIntMethod', 'NewStringUTF',
    'GetStringUTFChars', 'ReleaseStringUTFChars', 'FindClass', 'GetObjectClass'
]


def analyze_jni_symbols(so_file: str) -> Dict[str, List[str]]:
    """
    分析JNI相关符号
    
    Args:
        so_file: .so文件路径
        
    Returns:
        包含JNI符号分类的字典
    """
    rc, out, err = run_cmd(["nm", "-D", so_file])
    
    jni_symbols = {"jni_methods": [], "jni_vars": [], "other_jni": []}
    
    if rc == 0:
        for line in out.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # 解析nm输出格式
            parts = line.split()
            if len(parts) >= 3:
                symbol_type = parts[1]
                symbol_name = parts[2]
                
                # 检查是否为JNI相关符号
                for keyword in JNI_KEYWORDS:
                    if keyword in symbol_name.lower():
                        if symbol_type in ['T', 'W', 't', 'w']:  # 文本/弱符号（函数）
                            jni_symbols["jni_methods"].append(symbol_name)
                        elif symbol_type in ['D', 'B', 'd', 'b']:  # 数据符号
                            jni_symbols["jni_vars"].append(symbol_name)
                        else:
                            jni_symbols["other_jni"].append(symbol_name)
                        break
    
    return jni_symbols


def get_jni_summary(jni_symbols: Dict[str, List[str]]) -> dict:
    """
    获取JNI分析摘要
    
    Args:
        jni_symbols: JNI符号字典
        
    Returns:
        包含JNI分析摘要的字典
    """
    summary = {}
    
    summary["total_jni_methods"] = len(jni_symbols["jni_methods"])
    summary["total_jni_vars"] = len(jni_symbols["jni_vars"])
    summary["total_other_jni"] = len(jni_symbols["other_jni"])
    summary["total_jni"] = summary["total_jni_methods"] + summary["total_jni_vars"] + summary["total_other_jni"]
    
    # 统计JNI方法类型分布
    method_types = {}
    for method in jni_symbols["jni_methods"]:
        if "Java_" in method:
            method_types["Java_native"] = method_types.get("Java_native", 0) + 1
        elif "JNI_" in method:
            method_types["JNI_API"] = method_types.get("JNI_API", 0) + 1
        elif "RegisterNatives" in method:
            method_types["RegisterNatives"] = method_types.get("RegisterNatives", 0) + 1
        else:
            method_types["other"] = method_types.get("other", 0) + 1
    
    summary["jni_method_types"] = method_types
    
    # 计算风险分数
    summary["risk_score"] = summary["total_jni"] * 2
    
    return summary