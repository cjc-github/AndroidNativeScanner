"""
通用工具函数模块
包含外部命令执行、文件操作等通用功能
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional


def check_tools_exist() -> List[str]:
    """
    检查 REQUIRED_TOOLS 中列出的外部命令是否存在于 PATH。
    返回缺失的工具列表（空列表表示全部存在）。
    """
    REQUIRED_TOOLS = ["readelf", "nm", "strings"]
    
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