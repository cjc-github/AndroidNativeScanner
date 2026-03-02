"""
通用工具函数模块
包含外部命令执行、文件操作等通用功能
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional


REQUIRED_TOOLS = ["readelf", "nm", "strings"]


def check_tools_exist() -> List[str]:
    """
    检查 REQUIRED_TOOLS 中列出的外部命令是否存在于 PATH。
    返回缺失的工具列表（空列表表示全部存在）。
    """
    return [t for t in REQUIRED_TOOLS if shutil.which(t) is None]


def run_cmd(command: List[str], timeout: Optional[int] = 20) -> Tuple[int, str, str]:
    """
    安全地运行外部命令，并返回 (returncode, stdout, stderr)。
    使用 timeout 防止阻塞过久。
    """
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"[!] timeout after {timeout}s"
    except Exception as e:
        return -1, "", f"[!] Error running command {command}: {e}"


def extract_strings_from_so(so_path: str, min_length: int = 4) -> List[str]:
    """
    从 .so 文件中提取并过滤字符串。
    多个分析器共用此函数以避免重复调用 strings 命令。
    """
    rc, out, _ = run_cmd(["strings", so_path])
    if rc != 0:
        return []
    return [s for s in out.splitlines() if len(s) >= min_length]


def safe_write_report(path: Path, text: str):
    """将报告写入磁盘，确保父目录存在。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
