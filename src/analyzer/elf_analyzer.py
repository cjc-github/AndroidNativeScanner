"""
ELF头分析模块
负责分析.so文件的ELF头信息
"""

from typing import Dict

from ..utils import run_cmd


def analyze_elf_header(so_path: str) -> Dict:
    """
    分析ELF头信息
    
    Args:
        so_path: .so文件路径
        
    Returns:
        包含ELF头信息的字典
    """
    rc, out, err = run_cmd(["readelf", "-h", so_path])
    
    summary = {}
    
    if rc != 0:
        return summary
    
    lines = out.splitlines()
    for line in lines:
        line = line.strip()
        if "Type:" in line:
            summary["type"] = line.split("Type:")[1].strip()
        elif "Machine:" in line:
            summary["machine"] = line.split("Machine:")[1].strip()
        elif "Entry point address:" in line:
            summary["entry_point"] = line.split("Entry point address:")[1].strip()
        elif "Number of program headers:" in line:
            summary["program_headers"] = line.split("Number of program headers:")[1].strip()
        elif "Number of section headers:" in line:
            summary["section_headers"] = line.split("Number of section headers:")[1].strip()
    
    # 添加风险分数
    summary["risk_score"] = 0  # ELF头分析通常风险较低
    
    return summary


def get_elf_header_summary(elf_info: Dict) -> dict:
    """
    从ELF头信息中提取摘要信息
    
    Args:
        elf_info: analyze_elf_header返回的字典
        
    Returns:
        包含ELF头摘要信息的字典
    """
    return elf_info