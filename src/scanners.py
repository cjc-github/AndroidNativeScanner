"""
检测和扫描辅助函数模块
包含各种字符串检测和扫描功能
"""

import base64
import re
from typing import List, Tuple

# 敏感模式配置
SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "OpenAI Key": r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "JWT": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Password/Token": r"(?:pass(?:word)?|pwd|token|auth)[\"'=:\s]+[^\"\s]+"
}

# URL 匹配正则
_URL_RE = re.compile(r"https?://[^\s\"']+")

# Base64 候选字符串规则
_BASE64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
_BASE64_MAX_BYTES = 4096

# 预编译敏感模式正则
_COMPILED_SENSITIVE = {k: re.compile(v) for k, v in SENSITIVE_PATTERNS.items()}


def detect_base64_strings(strings: List[str]) -> List[Tuple[str, str]]:
    """
    在给定的字符串列表中识别可能是 base64 编码的项，并尝试解码。
    """
    results = []
    for s in strings:
        if not _BASE64_CANDIDATE.match(s):
            continue
        if len(s) > _BASE64_MAX_BYTES:
            continue
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
            try:
                decoded = decoded_bytes.decode("utf-8", errors="strict")
            except Exception:
                continue
            if sum(1 for c in decoded if c.isprintable()) / max(1, len(decoded)) > 0.6:
                results.append((s, decoded))
        except Exception:
            continue
    return results


def scan_sensitive_patterns(strings: List[str]) -> List[Tuple[str, str]]:
    """
    在字符串列表中使用预编译的敏感模式进行匹配。
    """
    findings = []
    for line in strings:
        for label, cre in _COMPILED_SENSITIVE.items():
            if cre.search(line):
                findings.append((label, line.strip()))
    return findings


def scan_urls(strings: List[str]) -> List[str]:
    """
    在字符串列表中查找硬编码 URL，返回 URL 列表。
    """
    found = []
    for s in strings:
        m = _URL_RE.search(s)
        if m:
            found.append(m.group(0))
    return found


def scan_jni_methods(strings: List[str]) -> List[str]:
    """
    在字符串列表中查找 JNI 风格的方法名（Java_...），返回包含这些字符串的行。
    """
    found = []
    for s in strings:
        if "Java_" in s:
            found.append(s.strip())
    return found