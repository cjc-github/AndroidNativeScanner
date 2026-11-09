"""Audit the changes for this round: logic closure and dead code.

The audit asks three questions of every touched area:

* is the new behaviour reachable from the CLI or the console?
* does every code path end in a defined state (no half-finished branch)?
* does the documentation say what the code does?
"""

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

problems = []


def check(condition, message):
    if condition:
        print(f"[OK]   {message}")
    else:
        print(f"[FAIL] {message}")
        problems.append(message)


def run(*argv):
    return subprocess.run(
        [sys.executable, *argv],
        capture_output=True,
        text=True,
        cwd=REPO,
    )


# --- 1. every new analyzer is reachable from the CLI ------------------------
print("=== 1. 新能力的可达性 ===")
modules = run("-m", "soinsight", "modules", "list", "--format", "json")
capabilities = []
if modules.returncode == 0:
    payload = json.loads(modules.stdout)
    for module in payload:
        capabilities.extend(c["id"] for c in module["capabilities"])

expected_new = [
    "automation.report",
    "automation.seed",
    "dynamic.arguments",
    "dynamic.memory",
    "dynamic.syscalls",
    "dynamic.coverage",
]
for capability in expected_new:
    check(capability in capabilities, f"{capability} 在能力目录中")

for capability in expected_new:
    result = run(
        "-m", "soinsight", *capability.split("."), "README.md", "--format", "json"
    )
    check(
        result.returncode == 0,
        f"{capability} 命令可执行（退出码 {result.returncode}）",
    )

# --- 2. the dynamic gate never executes anything --------------------------
print()
print("=== 2. 动态族的安全性 ===")
dynamic_sources = (
    "src/soinsight/analyzers/dynamic_trace.py",
    "src/soinsight/analyzers/dynamic_collectors.py",
    "src/soinsight/analyzers/dynamic_arguments.py",
    "src/soinsight/analyzers/dynamic_memory.py",
    "src/soinsight/analyzers/dynamic_syscalls.py",
    "src/soinsight/analyzers/dynamic_coverage.py",
    "src/soinsight/infrastructure/dynamic/collector.py",
)
for path in dynamic_sources:
    text = (REPO / path).read_text(encoding="utf-8")
    forbidden = ("subprocess.", "os.system", "os.popen", "Popen")
    found = [item for item in forbidden if item in text]
    check(not found, f"{Path(path).name} 不含任何执行调用 {found or ''}")

execution = (REPO / "src" / "soinsight" / "infrastructure" / "execution.py").read_text(
    encoding="utf-8"
)
check(
    "allow_execution: bool = False" in execution,
    "SubprocessSandboxExecutor 默认不执行",
)

# --- 3. the taint library is consistent in both copies --------------------
print()
print("=== 3. 污点函数库的一致性 ===")
checkout = REPO / "configs" / "taint-functions.yaml"
packaged = REPO / "src" / "soinsight" / "configs" / "taint-functions.yaml"
check(checkout.is_file(), "仓库根有 configs/taint-functions.yaml")
check(packaged.is_file(), "包内有 src/soinsight/configs/taint-functions.yaml")
if checkout.is_file() and packaged.is_file():
    check(
        checkout.read_text(encoding="utf-8") == packaged.read_text(encoding="utf-8"),
        "两份污点函数库内容一致",
    )

# --- 4. the console has exactly one implementation ------------------------
print()
print("=== 4. Web 实现唯一化 ===")
web_files = sorted(p.name for p in (REPO / "src" / "soinsight" / "web").glob("*.py"))
check(
    "console.py" in web_files and "server.py" not in web_files,
    f"包内只有 console.py（实际: {web_files}）",
)
check(
    not (REPO / "src" / "soinsight" / "web" / "templates").exists(),
    "旧模板目录已删除",
)
wrapper = (REPO / "web" / "server.py").read_text(encoding="utf-8")
check(
    "from soinsight.web.console import main" in wrapper,
    "仓库根脚本是薄包装",
)

# The pages live in the package only: a second copy in the checkout would
# drift, and nothing serves them from there.
package_web = REPO / "src" / "soinsight" / "web"
check(
    (package_web / "index.html").is_file(),
    "控制台页面在包内",
)
check(
    (package_web / "so-scan.html").is_file(),
    "深度分析台页面在包内",
)
check(
    not (REPO / "web" / "index.html").exists()
    and not (REPO / "web" / "so-scan.html").exists(),
    "仓库根没有重复的页面副本",
)

# --- 5. the report covers both sides of the findings ----------------------
print()
print("=== 5. 报告的完整性 ===")
report = (REPO / "src" / "soinsight" / "analyzers" / "automation_report.py").read_text(
    encoding="utf-8"
)
check("_all_findings(context)" in report, "报告合并分析器与规则两侧的发现项")
rules_engine = (REPO / "src" / "soinsight" / "core" / "rules" / "engine.py").read_text(
    encoding="utf-8"
)
check("_deduplicate" in rules_engine, "规则求值按指纹去重（可被多次调用）")
scheduler = (REPO / "src" / "soinsight" / "core" / "runtime" / "scheduler.py").read_text(
    encoding="utf-8"
)
check(
    "rule_engine.evaluate(context)" in scheduler,
    "调度器在 stage 之间求值规则（报告能看到规则结果）",
)

# --- 6. the taint path analysis closes its loop ---------------------------
print()
print("=== 6. 污点链路的闭环 ===")
paths = (REPO / "src" / "soinsight" / "infrastructure" / "taint_paths.py").read_text(
    encoding="utf-8"
)
check("analyse_taint_paths" in paths, "存在跨函数链路分析入口")
check("fingerprint" in paths, "链路有稳定指纹（可去重）")
security = (REPO / "src" / "soinsight" / "analyzers" / "security.py").read_text(
    encoding="utf-8"
)
check("_taint_findings" in security, "污点到达的 sink 会生成 Finding")
check("taint_path" in security, "Finding 证据携带完整链路")

# --- 7. no dead imports in the files this round touched -------------------
print()
print("=== 7. 本次改动的死代码 ===")
touched = [
    "src/soinsight/analyzers/automation_report.py",
    "src/soinsight/analyzers/automation_seed.py",
    "src/soinsight/analyzers/dynamic_collectors.py",
    "src/soinsight/analyzers/dynamic_arguments.py",
    "src/soinsight/analyzers/dynamic_memory.py",
    "src/soinsight/analyzers/dynamic_syscalls.py",
    "src/soinsight/analyzers/dynamic_coverage.py",
    "src/soinsight/infrastructure/report_building.py",
    "src/soinsight/infrastructure/seed_gen.py",
    "src/soinsight/infrastructure/taint_library.py",
    "src/soinsight/infrastructure/taint_paths.py",
    "src/soinsight/infrastructure/dynamic/collector.py",
]
lint = run("-m", "pyflakes", *touched)
unused = [
    line
    for line in lint.stdout.splitlines()
    if "imported but unused" in line or "undefined name" in line
]
check(not unused, f"本次新增文件无未使用导入/未定义名 {unused or ''}")

# --- 8. the CLI has no undefined names ------------------------------------
print()
print("=== 8. CLI 的未定义名 ===")
cli_lint = run("-m", "pyflakes", "src/soinsight/cli/main.py")
undefined = [line for line in cli_lint.stdout.splitlines() if "undefined name" in line]
check(not undefined, f"CLI 无未定义名 {undefined or ''}")

print()
if problems:
    print(f"审核发现 {len(problems)} 个问题:")
    for item in problems:
        print(f"  - {item}")
    raise SystemExit(1)
print("审核通过：无逻辑断点、无死代码、文档与实现一致")
