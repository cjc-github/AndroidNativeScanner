"""
命令行解析和入口逻辑模块
包含参数解析和主程序逻辑
"""

import argparse
import concurrent.futures
import json
from datetime import datetime
from pathlib import Path
from termcolor import colored

from .utils import check_tools_exist
from .analyzer import analyze_so_file, get_analysis_summary


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


def generate_report(so_file: Path, results: dict, summary: dict, out_dir: Path, quiet: bool = False):
    """
    生成分析报告
    
    Args:
        so_file: .so文件路径
        results: 分析结果
        summary: 分析摘要
        out_dir: 输出目录
        quiet: 静默模式
    """
    # 生成报告文件名
    report_file = out_dir / f"report_{so_file.name}.txt"
    
    
    # 清理字符串分析结果
    results["strings"] = {
        "all": [],
        "filtered": []
    }
    
    # 生成报告内容
    report_content = f"""Android Native Scanner Report
{'='*50}
File: {so_file}
Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Level: {summary['risk_level']}
Total Risk Score: {summary['total_risk_score']}

Summary:
- ELF Header Analysis: {summary['elf_summary']['risk_score']} risk points
- Symbol Analysis: {summary['symbol_summary']['risk_score']} risk points
- String Analysis: {summary['string_summary']['risk_score']} risk points
- Sensitive Patterns: {summary['sensitive_summary']['risk_score']} risk points
- URL Detection: {summary['url_summary']['risk_score']} risk points
- Base64 Detection: {summary['base64_summary']['risk_score']} risk points
- JNI Analysis: {summary['jni_summary']['risk_score']} risk points

Detailed Results:
{json.dumps(results, indent=2, ensure_ascii=False)}
"""
    
    # 写入报告文件
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    if not quiet:
        print(colored(f"[✓] Report generated: {report_file}", "green"))


def analyze_and_report(so_file: Path, out_dir: Path, quiet: bool = False):
    """
    分析.so文件并生成报告
    
    Args:
        so_file: .so文件路径
        out_dir: 输出目录
        quiet: 静默模式
    """
    try:
        if not quiet:
            print(colored(f"[i] Analyzing {so_file}", "cyan"))
        
        # 执行分析
        results = analyze_so_file(str(so_file))
        summary = get_analysis_summary(results)
        
        # 生成报告
        generate_report(so_file, results, summary, out_dir, quiet)
        
        if not quiet:
            print(colored(f"[✓] Analysis completed for {so_file}", "green"))
            
    except Exception as e:
        print(colored(f"[!] Error analyzing {so_file}: {e}", "red"))


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
        analyze_and_report(in_path, out_dir, args.quiet)
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
            futures.append(ex.submit(analyze_and_report, so, out_dir, args.quiet))
        # 等待所有任务完成，并处理异常
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as e:
                # 捕获单个任务异常，继续处理其他任务
                print(colored(f"[!] Error during analysis: {e}", "red"))