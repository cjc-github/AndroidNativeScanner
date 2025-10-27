#!/usr/bin/env python3
"""
Android Native Scanner - improved version（带注释）
- 并发目录扫描
- 更安全的外部命令调用与超时处理
- 预编译正则、改进的 base64 检测
- 结构化风险计分与可配置选项
"""

from __future__ import annotations
import argparse
import base64
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Optional
from termcolor import colored

# -----------------------
# 配置与正则模式定义
# -----------------------

# 与远程命令执行 / 动态加载相关的关键词，用于在符号中查找可疑项
RCE_KEYWORDS = [
    'system', 'exec', 'sh', '/bin', 'chmod', 'su', 'curl', 'wget', 'eval',
    'Runtime', 'loadLibrary', 'popen', 'dlopen', 'dlsym', 'fopen', 'strcpy', 'sprintf'
]

# 常见的敏感密钥/令牌模式（正则）
SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "OpenAI Key": r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    # JWT 模式（简化版，可能会误报）
    "JWT": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    # 通用 password/token 检测（非常宽松，可能大量误报）
    "Password/Token": r"(?:pass(?:word)?|pwd|token|auth)[\"'=:\s]+[^\"\s]+"
}

# 预编译正则，提高匹配效率并减少重复编译开销
_COMPILED_SENSITIVE = {k: re.compile(v) for k, v in SENSITIVE_PATTERNS.items()}

# URL 匹配用于查找硬编码 URL
_URL_RE = re.compile(r"https?://[^\s\"']+")

# JNI 方法签名（以 Java_ 开头的本地方法名）
_JNI_RE = re.compile(r"Java_[A-Za-z0-9_]+")

# 简单的 base64 候选字符串规则：仅包含 base64 字符，长度至少 20
_BASE64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/=]{20,}$")

# 为了避免内存爆炸，限制待解码 base64 字符串的长度（字节数）
_BASE64_MAX_BYTES = 4096

# 依赖的外部工具（脚本会调用这些工具）
REQUIRED_TOOLS = ["readelf", "nm", "strings"]

# -----------------------
# 通用工具函数
# -----------------------

def check_tools_exist() -> List[str]:
    """
    检查 REQUIRED_TOOLS 中列出的外部命令是否存在于 PATH。
    返回缺失的工具列表（空列表表示全部存在）。
    """
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    return missing

def run_cmd(command: List[str], timeout: Optional[int] = 20) -> Tuple[int, str, str]:
    """
    安全地运行外部命令，并返回 (returncode, stdout, stderr)。
    使用 timeout 防止阻塞过久。
    """
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        # 超时返回特殊错误码 -1，并在 stderr 中说明
        return -1, "", f"[!] timeout after {timeout}s"
    except Exception as e:
        # 捕获其他异常并把信息放入 stderr
        return -1, "", f"[!] Error running command {command}: {e}"

def safe_write_report(path: Path, text: str):
    """
    将报告写入磁盘，确保父目录存在。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

# -----------------------
# 检测/扫描辅助函数
# -----------------------

def detect_base64_strings(strings: List[str]) -> List[Tuple[str, str]]:
    """
    在给定的字符串列表中识别可能是 base64 编码的项，并尝试解码。
    - 仅对通过 _BASE64_CANDIDATE 的字符串进行解码尝试
    - 使用 base64.b64decode(..., validate=True) 以确保合法性
    - 限制最大字节长度避免死内存分配
    - 仅返回可解码为 UTF-8 且含大量可打印字符的解码结果
    返回值为 [(原始base64, 解码后文本), ...]
    """
    results = []
    for s in strings:
        # 候选过滤：格式与长度
        if not _BASE64_CANDIDATE.match(s):
            continue
        if len(s) > _BASE64_MAX_BYTES:
            # 过长的不尝试以避免内存/CPU 占用
            continue
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
            # 尝试用严格 UTF-8 解码
            try:
                decoded = decoded_bytes.decode("utf-8", errors="strict")
            except Exception:
                # 不是可读文本（可能是二进制或非 UTF-8），跳过
                continue
            # 要求解码结果有较高比例的可打印字符，避免误报二进制
            if sum(1 for c in decoded if c.isprintable()) / max(1, len(decoded)) > 0.6:
                results.append((s, decoded))
        except Exception:
            # 解码失败的都忽略
            continue
    return results

def scan_sensitive_patterns(strings: List[str]) -> List[Tuple[str, str]]:
    """
    在字符串列表中使用预编译的敏感模式进行匹配。
    返回值列表 [(标签, 匹配行), ...]
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
        if _JNI_RE.search(s):
            found.append(s.strip())
    return found

# -----------------------
# 单文件分析主逻辑
# -----------------------

def analyze_so_file(so_path: Path, out_dir: Path, timeout: int = 20, quiet: bool = False) -> None:
    """
    分析单个 .so 文件并生成一份文本报告（写到 out_dir）。
    参数:
      - so_path: 待分析的 .so 文件路径
      - out_dir: 报告输出目录（会写 report_<so>.txt）
      - timeout: 调用外部工具的超时（秒）
      - quiet: 如果 True 则不在终端打印大量信息，仅写文件
    分析内容包含：
      - ELF Header (readelf -h)
      - Exported Symbols (nm -D)
      - 从符号中查找与 RCE 相关关键字
      - strings 输出中的敏感模式、URL、base64、JNI 方法
      - 风险评分（根据发现类型累加）
    """
    # 检查文件是否存在
    if not so_path.exists() or not so_path.is_file():
        if not quiet:
            print(colored(f"[!] File not found: {so_path}", "red"))
        return

    # 用于在终端和报告中输出的缓冲区
    report_lines: List[str] = []

    def log_console(msg: str, color: Optional[str] = None):
        """
        内部打印函数：若非 quiet 则在终端以彩色输出，同时把原始文本（去掉 ANSI 码）追加到 report_lines。
        """
        if not quiet:
            print(colored(msg, color) if color else msg)
        # 将 ANSI 颜色序列移除后写入报告行
        report_lines.append(re.sub(r'\x1b\[[0-9;]*m', '', msg))

    base_name = so_path.name
    log_console(f"[*] Android Native Scanner - Analyzing: {so_path}\n")

    # 1) ELF header 信息
    rc, out, err = run_cmd(["readelf", "-h", str(so_path)], timeout=timeout)
    if rc == 0:
        log_console("[+] ELF Header Info:")
        log_console(out)
    else:
        # 若 readelf 出错则打印警告，但继续后续分析（可能是非 ELF 文件）
        log_console(f"[!] readelf failed: {err}", "yellow")

    # 2) 导出符号（nm -D）
    rc, nm_out, nm_err = run_cmd(["nm", "-D", str(so_path)], timeout=timeout)
    if rc == 0 and nm_out:
        log_console("\n[+] Exported Symbols:")
        log_console(nm_out)
    else:
        log_console(f"\n[!] nm failed or returned nothing: {nm_err}", "yellow")
        nm_out = nm_out or ""

    # 3) 在符号中查找 RCE 相关关键词，并记录风险分
    rce_matches = [line for line in nm_out.splitlines() if any(k in line for k in RCE_KEYWORDS)]
    risk_score = 0
    if rce_matches:
        # 高亮显示 RCE 相关符号
        log_console("\n[+] RCE-Related Symbols:", "red")
        for match in rce_matches:
            log_console(f"[*] {match}", "red")
            risk_score += 5  # 每发现一项增加风险分（可调）
    else:
        log_console("\n[-] No suspicious symbols found.")

    # 4) 提取 strings（可能很长）
    rc, str_out, str_err = run_cmd(["strings", str(so_path)], timeout=timeout)
    if rc != 0:
        log_console(f"\n[!] strings command failed: {str_err}", "yellow")
        strings_output = []
    else:
        # 将 strings 输出按行保存以便后续多种检测复用
        strings_output = str_out.splitlines()

    # 5) 敏感数据模式检测
    sens = scan_sensitive_patterns(strings_output)
    if sens:
        log_console("\n[+] Sensitive Data Detected:")
        for label, line in sens:
            log_console(f"[!] {label}: {line}", "green")
            # 根据标签类型给不同权重的风险分
            if "Key" in label or "Token" in label:
                risk_score += 4
            elif "JWT" in label:
                risk_score += 3
            else:
                risk_score += 2
    else:
        log_console("\n[-] No sensitive patterns found.")

    # 6) 查找硬编码 URL
    urls = scan_urls(strings_output)
    if urls:
        log_console("\n[+] Hardcoded URLs:")
        for url in urls:
            log_console(f"[*] URL: {url}", "green")
            risk_score += 2
    else:
        log_console("\n[-] No hardcoded URLs found.")

    # 7) 检测 base64 并尽量解码（仅展示预览避免爆行）
    b64s = detect_base64_strings(strings_output)
    if b64s:
        log_console("\n[+] Base64-Encoded Strings (decoded):")
        for b64, decoded in b64s:
            # 若解码文本很长，只显示前 400 字符作为预览并标注截断
            short_decoded = decoded if len(decoded) <= 400 else decoded[:400] + " ...(truncated)"
            log_console(f"[*] Encoded: {b64}\n    → Decoded (preview): {short_decoded}")
            # base64 内可能包含密钥、脚本等，增加一定风险分
            risk_score += 2
    else:
        log_console("\n[-] No likely base64-encoded text found.")

    # 8) 查找 JNI 方法
    jnis = scan_jni_methods(strings_output)
    if jnis:
        log_console("\n[+] JNI Methods:")
        for j in jnis:
            log_console(f"[*] {j}")
    else:
        log_console("\n[-] No JNI method symbols found in strings.")

    # 9) 风险评分汇总与分级
    log_console(f"\n[+] Final Risk Score: {risk_score}")
    # 阈值：>=12 High, >=6 Medium, else Low；可按需调整
    if risk_score >= 12:
        log_console("[!] Risk Level: HIGH ⚠️", "red")
    elif risk_score >= 6:
        log_console("[!] Risk Level: MEDIUM ⚠", "yellow")
    else:
        log_console("[+] Risk Level: LOW ✅", "green")

    # 尾注
    log_console("\n[✓] Analysis complete. Powered by Android Native Scanner")

    # 将报告写为纯文本（移除 ANSI 颜色），文件名：report_<so>.txt
    report_path = out_dir / f"report_{base_name}.txt"
    safe_write_report(report_path, "\n".join(report_lines))
    if not quiet:
        print(colored(f"[i] Report written to {report_path}", "cyan"))

# -----------------------
# 命令行解析与入口逻辑
# -----------------------

def parse_args():
    """
    解析命令行参数：
      - path: 要分析的 .so 文件或目录
      - --out/-o: 报告输出目录
      - --jobs/-j: 并行 worker 数（仅目录模式有效）
      - --timeout/-t: 外部工具超时（秒）
      - --quiet/-q: 静默模式（仅写报告，不打印大量信息）
    """
    p = argparse.ArgumentParser(
        description="Android Native Scanner - analyze .so files for RCE, sensitive data, keys, URLs, JNI."
    )
    p.add_argument("path", help="Path to .so file or directory containing .so files")
    p.add_argument("-o", "--out", default="reports", help="Output directory for reports (default: reports)")
    p.add_argument("-j", "--jobs", type=int, default=4, help="Parallel workers for directory scan (default: 4)")
    p.add_argument("-t", "--timeout", type=int, default=20, help="Timeout seconds for external tools (default: 20)")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (less console output)")
    return p.parse_args()

def main():
    """
    程序入口：
      - 解析参数
      - 检查依赖工具（readelf/nm/strings），若缺失则提醒
      - 单文件模式直接分析
      - 目录模式收集所有 .so，用线程池并发分析
    """
    args = parse_args()
    in_path = Path(args.path)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 提示缺失外部工具（但不强制退出，依赖命令会在使用时返回错误）
    missing = check_tools_exist()
    if missing:
        print(colored(f"[!] Missing required external tools: {', '.join(missing)}", "red"))
        print("    Please install these tools (e.g. apt install binutils strings) and re-run.")

    # 如果输入是文件，直接分析
    if in_path.is_file():
        analyze_so_file(in_path, out_dir, timeout=args.timeout, quiet=args.quiet)
        return

    # 如果输入是目录，递归收集 .so 文件
    so_files = [p for p in in_path.rglob("*.so") if p.is_file()]
    if not so_files:
        print(colored(f"[!] No .so files found under {in_path}", "yellow"))
        return

    if not args.quiet:
        print(colored(f"[i] Found {len(so_files)} .so files. Scanning with {args.jobs} workers...", "cyan"))

    # 使用线程池并发分析每个文件（IO 与外部命令为主，线程池通常表现良好）
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = []
        for so in so_files:
            futures.append(ex.submit(analyze_so_file, so, out_dir, args.timeout, args.quiet))
        # 等待所有任务完成，并处理异常
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as e:
                # 捕获单个任务异常，继续处理其他任务
                print(colored(f"[!] Error during analysis: {e}", "red"))

# 如果以脚本方式执行，调用 main()
if __name__ == "__main__":
    main()
