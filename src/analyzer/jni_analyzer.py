"""
JNI 方法分析模块
检测 .so 文件中的 JNI 相关符号和方法
"""

from typing import Any, Dict, List

from .base import BaseAnalyzer
from ..utils import run_cmd

JNI_KEYWORDS = [
    "jni", "Java", "JNI_", "RegisterNatives", "GetMethodID", "GetFieldID",
    "CallVoidMethod", "CallObjectMethod", "CallIntMethod", "NewStringUTF",
    "GetStringUTFChars", "ReleaseStringUTFChars", "FindClass", "GetObjectClass",
]


class JniAnalyzer(BaseAnalyzer):
    name = "JNI分析"
    key = "jni"
    summary_key = "jni_summary"

    def analyze(self, so_file: str, **context) -> Dict[str, List[str]]:
        rc, out, _ = run_cmd(["nm", "-D", so_file])

        jni_symbols: Dict[str, List[str]] = {
            "jni_methods": [],
            "jni_vars": [],
            "other_jni": [],
        }

        if rc != 0:
            return jni_symbols

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            sym_type, sym_name = parts[1], parts[2]
            for kw in JNI_KEYWORDS:
                if kw in sym_name.lower():
                    if sym_type in ("T", "W", "t", "w"):
                        jni_symbols["jni_methods"].append(sym_name)
                    elif sym_type in ("D", "B", "d", "b"):
                        jni_symbols["jni_vars"].append(sym_name)
                    else:
                        jni_symbols["other_jni"].append(sym_name)
                    break

        return jni_symbols

    def summarize(self, results: Any) -> Dict[str, Any]:
        methods = results.get("jni_methods", [])
        vars_ = results.get("jni_vars", [])
        other = results.get("other_jni", [])
        total = len(methods) + len(vars_) + len(other)

        method_types: Dict[str, int] = {}
        for m in methods:
            if "Java_" in m:
                method_types["Java_native"] = method_types.get("Java_native", 0) + 1
            elif "JNI_" in m:
                method_types["JNI_API"] = method_types.get("JNI_API", 0) + 1
            elif "RegisterNatives" in m:
                method_types["RegisterNatives"] = method_types.get("RegisterNatives", 0) + 1
            else:
                method_types["other"] = method_types.get("other", 0) + 1

        return {
            "total_jni_methods": len(methods),
            "total_jni_vars": len(vars_),
            "total_other_jni": len(other),
            "total_jni": total,
            "jni_method_types": method_types,
            "risk_score": total * 2,
        }
