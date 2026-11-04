# SOInsight 快速使用

SOInsight（命令 `soinsight`）对 Linux/Android ELF 动态库（`.so`）做本地静态分析。本页只覆盖最简用法；完整参数、YAML 字段与设计细节见 `docs/archive/` 与 `design/`。

## 0. 一键启动（推荐）

不想手动建环境、装依赖，用仓库根目录的启动脚本。它会自动判断 Python 版本（≥3.10）、创建/复用 `.venv`、按 `pip-mirrors.toml` 里的配置装依赖，然后启动本地 Web 控制台并在浏览器打开。

```bash
# Linux / macOS
./start.sh

# 指定端口（默认 8791，也可用环境变量 SOINSIGHT_PORT）
./start.sh --port 9000

# 不自动打开浏览器、调整单次分析超时
./start.sh --no-open --timeout 600
```

```powershell
# Windows（PowerShell）
powershell -ExecutionPolicy Bypass -File start.ps1
powershell -ExecutionPolicy Bypass -File start.ps1 -Port 9000
```

脚本行为：

- 已存在 `.venv` 就直接复用，不会每次重装；
- 依赖按 `requirements.txt` 的哈希判断是否要重装，改过依赖清单才会重新安装；
- 完整过程写入 `logs/start.log`，出问题直接贴这个文件；
- 额外参数会透传给 `web/server.py`（`--port` / `--host` / `--timeout` / `--no-open`）。

换 pip 镜像源改 `pip-mirrors.toml` 的 `active` 一行即可，不用动脚本，详见 [pip 镜像源配置](pip-mirrors.md)。

## 1. 安装

想直接用命令行而不是网页，有两种方式。

源码目录内免安装运行：

```bash
PYTHONPATH=src python3 -m soinsight --help
```

可编辑安装（推荐，先建虚拟环境）：

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e '.[dev]'
soinsight --version
```

国内网络装得慢时换镜像，例如阿里云：

```bash
python -m pip install -e '.[dev]' -i https://mirrors.aliyun.com/pypi/simple/
```

其他镜像和切换方式见 [pip 镜像源配置](pip-mirrors.md)。

## 2. 环境自检

```bash
soinsight doctor
soinsight modules list
```

## 3. 常用命令

```bash
# 文件与 ELF 基础信息
soinsight basic file libfoo.so
soinsight basic elf libfoo.so

# 导出符号与函数签名（C++ demangle、JNI 解码）
soinsight basic symbols libfoo.so

# DWARF 调试信息（参数名/参数类型、返回类型、声明位置）
soinsight basic dwarf libfoo.so

# 安全加固与危险 API
soinsight security hardening libfoo.so
soinsight security dangerous-api libfoo.so

# 组合扫描：跨模块，只运行已实现的能力
soinsight scan libfoo.so --module-available basic,security
```

## 4. 输出

```bash
--format text|json|markdown|html|sarif   # 默认 text
-o result.json                           # 结果写入文件
--quiet                                  # 成功时完全静默（关闭进度行与文本结果）
```

## 5. 可复用 YAML 配置

```bash
soinsight config create quick-security
soinsight config set quick-security analysis.modules.basic '[file, elf]'
soinsight config use quick-security
soinsight scan libfoo.so
```

## 6. Web 控制台（可选）

不想敲命令时，可启动一个本地网页控制台，在浏览器里选择 .so 文件、勾选能力后一键分析，结果以卡片形式展示（ELF 头、符号表、发现项、DWARF 等）。

```bash
# 一键启动（自动建环境、装依赖），推荐
./start.sh                        # Linux / macOS
powershell -ExecutionPolicy Bypass -File start.ps1   # Windows

# 环境已就绪时，直接起服务
python3 web/server.py             # 默认 http://127.0.0.1:8765，占用则顺延
python3 web/server.py --port 9000 # 指定端口
python3 web/server.py --no-open   # 不自动打开浏览器
```

用浏览器打开提示的地址即可。支持三种目标来源：**拖拽 / 点击上传 .so 文件**、**填写服务器上已有的绝对路径**、**直接选 `in/` 目录里的样本**。分析后端就是 `soinsight` CLI（`--format json`），所以 CLI 能跑的能力，网页里都能跑。

`web/so-scan.html` 是单独的「深度分析台」：一键全量扫描 + 实时滚动日志 + 结果摘要，适合不想勾选能力、直接看全量的场景。

> 仅监听本机 `127.0.0.1`，不上传任何数据到外部网络；非 ELF 文件或非法路径会被直接拒绝。
> 分析结果 JSON 会存到 `reports/` 目录，「结果 JSON」Tab 里给出路径与下载入口，页面不内联渲染数 MB 的完整数据。

## 注意事项

- 六大模块共 46 项能力；架构上，ELF 解析覆盖 17 种 e_machine，指令解码覆盖 x86/x86-64/ARM/AArch64/MIPS/PowerPC/RISC-V/S390/SPARC/SuperH/68K（32 位 ARM 支持 Thumb），交叉引用的引用解析覆盖 x86/ARM/AArch64。已实现的是 `basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`basic.types`、`basic.cpp`、`basic.disasm`、`basic.cfg`、`basic.callgraph`、`basic.dataflow`、`basic.dynamic`、`basic.xref`、`advanced.strings`、`advanced.constants`、`advanced.algorithm`、`advanced.protocol`、`advanced.file-format`、`advanced.library`、`advanced.compiler`、`advanced.obfuscation`、`security.hardening`、`security.dangerous-api`、`security.vulnerability`、`security.risk`、`security.dynamic-loading`、`basic.jni`、`automation.fuzz-target`、`automation.harness`；调用未实现的能力会返回 `ANALYSIS_PLAN_ERROR`（退出码 3）。
- `--module` 是严格展开（要求模块内能力全部已实现），日常请用 `--module-available`。
- V1 旧入口仍可用：`python3 main.py libfoo.so`。

## CI 用法（Gate 与基线）

```bash
# 建立基线并确认当前状态（按 high 阈值判定，退出码 6 表示未通过）
soinsight scan libfoo.so --module-available basic,security \
  --fail-on high --update-baseline .soinsight/baseline.json

# CI 中只拦新问题
soinsight scan libfoo.so --module-available basic,security \
  --fail-on high --baseline .soinsight/baseline.json
```

基线内的问题仍会出现在报告里（标 `suppressed`/`[baselined]`），只是不再阻断构建。

## 动态分析（默认拒绝执行）

`dynamic.*` 会执行目标，因此默认拒绝。只有在配置中显式授权后才会继续判定：

```yaml
# 例如写在 ~/.config/soinsight/config.yaml 或项目配置里
dynamic_execution:
  authorized: true
  allow_targets: ["/opt/samples/libfoo.so"]   # 可选白名单
```

```bash
soinsight dynamic trace libfoo.so   # 未授权 → not-authorized；已授权但无沙箱 → no-sandbox
```

隔离靠探测（`bwrap` > `firejail` > `docker` > `unshare`），探测不到就拒绝，**不会**在宿主上裸跑。
当前 `dynamic.trace` 只产出沙箱执行计划（含超时/内存上限），不启动进程、不采集事件。

## 版本对比（Binary Diff）

```bash
soinsight diff old.so new.so            # 符号级：新增 / 移除 / 移动 / 大小变化
soinsight diff old.so new.so --format json
```

纯静态对比，秒级出结果；函数体级与 CFG 级差异不在范围内。

## 更多文档

- 原详细使用文档（快速开始/使用手册/命令参考/YAML 配置）：`docs/archive/`
- 模块体系与 46 项能力清单：`docs/module-system.md`
- 项目状态与路线图：`docs/project-status.md`
- 设计与扩展开发：`design/design_v2.0.md`、`docs/extension-development.md`
