# SOInsight / Android Native Scanner

SOInsight 是面向 Linux/Android ELF 动态库（主要为 `.so`）的本地分析工具项目。

仓库当前并行保留：

- **V1（已有分析能力）**：Android Native Scanner，入口为 `python3 main.py`；
- **V2（新 CLI 工具箱框架）**：入口为 `soinsight` 或 `python3 -m soinsight`。

V2 的产品结构以六个一级能力域组织，而不是按内部技术组件分类：

1. **基础分析**（`basic`）
2. **高级分析**（`advanced`）
3. **安全分析**（`security`）
4. **动态分析**（`dynamic`）
5. **AI 分析**（`ai`）
6. **自动化**（`automation`）

Analyzer、Rule、Planner、Scheduler、Renderer、Artifact Store 等属于六大模块共享的内部实现机制，不是产品一级模块。

> 里程碑快照（2026-10-29）：六大模块目录、40 项原始能力、2 项自动化增强能力以及为动态链接与交叉引用新增的 3 项能力（`basic.dynamic`、`basic.xref`、`security.dynamic-loading`）的命令外壳已经建立，advanced 八项能力已全部落地；当时 `basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`basic.types`、`basic.cpp`、`basic.disasm`、`basic.cfg`、`basic.callgraph`、`basic.dataflow`、`basic.dynamic`、`basic.xref`、`advanced.strings`、`advanced.constants`、`advanced.algorithm`、`security.hardening`、`security.dangerous-api`、`security.vulnerability`、`security.risk`、`security.dynamic-loading` Analyzer（外加三条内置安全规则）已实现，其余 Analyzer 当时尚未迁移。
>
> **现在完整、最新的实现/未实现清单见下文「SO 分析能力现状」一节（快照 2026-11-09，已实现 36/46）。**

## 文档导航

| 文档 | 内容 |
|---|---|
| [快速使用](docs/quickstart.md) | 一键启动、安装、最常用命令和输出选项（一页） |
| [pip 镜像源配置](docs/pip-mirrors.md) | 切换国内镜像，解决安装慢的问题 |
| [模块体系](docs/module-system.md) | 六大产品模块、46 项能力及跨域依赖规则 |
| [项目状态与路线图](docs/project-status.md) | 已完成、未实现和下一阶段验收标准 |
| [架构说明](docs/architecture.md) | 产品能力层与技术实现层的关系 |
| [扩展开发指南](docs/extension-development.md) | 为能力实现 Analyzer、Rule、Profile、Renderer |
| [开发标准与迭代流程](docs/development-standards.md) | 提交前必须满足的条件、可执行的守卫与迭代闭环 |
| [V1 到 V2 迁移](docs/migration-v1-to-v2.md) | 迁移原则、领域映射和顺序 |
| [详细使用文档归档](docs/archive/) | 原快速开始/使用手册/CLI 命令参考/YAML 配置指南 |
| [V2 软件设计说明书](design/design_v2.0.md) | 六大能力域、CLI、设计模式与详细架构的唯一主设计 |
| [V3 设计占位](design/design_v3.0.md) | V3 尚未启动及其启动条件 |
| [V1 历史规划](design/design_v1.0.md) | 历史参考 |

## 快速运行

第一次使用，直接在仓库根目录跑启动脚本，它会自动判断 Python 版本、创建虚拟环境、安装依赖并打开本地 Web 控制台：

```bash
./start.sh                                        # Linux / macOS
powershell -ExecutionPolicy Bypass -File start.ps1   # Windows
```

```bash
./start.sh --port 9000      # 换端口（默认 8791）
./start.sh --no-open        # 不自动打开浏览器
```

镜像源在 `pip-mirrors.toml` 里配置（默认阿里云），换源只改 `active` 一行，详见 [pip 镜像源配置](docs/pip-mirrors.md)。完整启动日志写在 `logs/start.log`。

直接用命令行：

```bash
# 无安装运行
PYTHONPATH=src python3 -m soinsight --help
PYTHONPATH=src python3 -m soinsight modules list
PYTHONPATH=src python3 -m soinsight modules show basic
PYTHONPATH=src python3 -m soinsight doctor

# 领域命令（46 项能力中 36 项已实现，其余为能力外壳）
PYTHONPATH=src python3 -m soinsight basic elf README.md --format json
PYTHONPATH=src python3 -m soinsight basic symbols libfoo.so
PYTHONPATH=src python3 -m soinsight basic dwarf libfoo.so --format json
PYTHONPATH=src python3 -m soinsight advanced strings libfoo.so
PYTHONPATH=src python3 -m soinsight security hardening README.md
PYTHONPATH=src python3 -m soinsight security dangerous-api libfoo.so
PYTHONPATH=src python3 -m soinsight security risk libfoo.so --format json

# 报告与种子
PYTHONPATH=src python3 -m soinsight automation report libfoo.so --format json
PYTHONPATH=src python3 -m soinsight automation seed libfoo.so

# 多目标与目录批量扫描（--include/--exclude 过滤）
PYTHONPATH=src python3 -m soinsight scan libfoo.so libbar.so --enable basic.file
PYTHONPATH=src python3 -m soinsight scan libs/ --include '*.so' --format json

# 创建并使用可复用 YAML 分析配置
PYTHONPATH=src python3 -m soinsight config create quick-security
PYTHONPATH=src python3 -m soinsight config set quick-security analysis.modules.basic '[file, elf]'
PYTHONPATH=src python3 -m soinsight config use quick-security
PYTHONPATH=src python3 -m soinsight scan README.md
```

可编辑安装（推荐先创建虚拟环境，避免系统 Python 目录权限问题）：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e .
soinsight --version
soinsight modules list
```

运行测试：

```bash
# 若已激活 .venv，可直接复用该环境
python -m pip install -e '.[dev]'
python -m pytest -q
```
构建可安装 CLI Wheel：

```bash
./scripts/build_cli.sh
python -m pip install --force-reinstall dist/soinsight-*.whl
soinsight --help
```

构建后直接安装：

```bash
./scripts/build_cli.sh --install
```

## 本地 Web 控制台

仓库自带一个只绑定回环地址的本地控制台（仅标准库，无需额外依赖）。它把浏览器和 CLI 连起来：页面选文件 → 勾选分析能力 → 后台以子进程跑 `python -m soinsight ... --format json` → 结果按 Analyzer 分 Tab 展示。

```bash
./start.sh                       # 一键：建环境 + 装依赖 + 启动（推荐）
python3 web/server.py            # 环境已就绪时直接起（默认 8765，被占用则顺延）
python3 web/server.py --port 9000
python3 web/server.py --no-open
python3 web/server.py --timeout 600
soinsight web                    # 同一控制台（包内入口，不自动打开浏览器）
```

控制台实现在包内 `soinsight/web/console.py`，仓库根的 `web/server.py` 是它的薄包装，
因此脚本与 `soinsight web` 跑的是同一份代码。

- 支持拖拽上传、服务器绝对路径、`in/` 目录样本三种目标来源；上传文件写入临时目录，分析后删除；
- 分析能力支持任意多选（依赖自动补齐），也可切到「组合扫描」跑全部已实现 Analyzer；
- 运行中可点「停止分析」终止子进程；结果可复制/下载 JSON，符号表与发现项可导出 CSV；
- 结果 JSON 由服务端存到 `reports/`，页面只给路径和下载入口，不内联渲染数 MB 的完整数据；
- `src/soinsight/web/so-scan.html` 是单独的「深度分析台」：一键全量扫描 + 实时日志 + 结果摘要；
- `soinsight web` 与 `web/server.py` 是同一个控制台的两个入口，功能完全一致。

## 当前仓库结构

```text
AndroidNativeScanner/
├── start.sh / start.ps1        # 一键启动：自动建 venv、装依赖、起 Web 控制台
├── pip-mirrors.toml            # pip 镜像源配置（active 一行切换）
├── main.py                     # V1 入口
├── src/
│   ├── analyzer/               # V1 具体分析器
│   ├── cli.py                  # V1 CLI
│   └── soinsight/              # V2 CLI 工具箱
│       ├── modules/            # 六大产品能力域及能力目录
│       │   ├── basic/
│       │   ├── advanced/
│       │   ├── security/
│       │   ├── dynamic/
│       │   ├── ai/
│       │   └── automation/
│       ├── cli/                # CLI 适配层
│       ├── application/        # 应用服务层
│       ├── core/               # Analyzer/Rule/Planner/Runtime 等共享机制
│       ├── analyzers/          # 具体 Analyzer 注册位置
│       ├── renderers/          # Text/JSON/Markdown/HTML/SARIF 输出
│       └── infrastructure/     # 配置、工具、存储、插件边界
│           ├── elf/            # 纯 Python ELF 解析 + C++ demangle + JNI 解码
│           ├── dwarf/          # 纯 Python DWARF 调试信息解析
│           ├── dynamic/        # 动态采集底座：授权门、驱动计划、dlopen harness
│           ├── report_building.py  # 报告文档构建（按分析器分节）
│           └── seed_gen.py     # 种子语料生成（格式/协议/常量事实）
├── tests/                      # V2 单元与集成测试
├── web/                        # 本地 Web 控制台：server.py / index.html / so-scan.html
├── scripts/build_cli.sh        # Wheel 构建与入口校验
├── docs/                       # 使用与开发文档
└── design/                     # V2 主设计、V3 占位与 V1 历史规划
```

## SO 分析能力现状（实现 / 未实现）

> 快照日期：2026-11-09。以 `PYTHONPATH=src python3 -m soinsight modules list` 与注册代码
> `analyzers/builtin.py` 逐项核对：六大模块共 **46 项能力**，**36 项已接入真实 Analyzer（✅）**，
> **10 项只有目录/命令外壳（保持未勾选）**。调用未实现能力返回 `ANALYSIS_PLAN_ERROR`（退出码 3）。
> 逐项细节见 [项目状态与路线图](docs/project-status.md)、[功能实现状态清单](docs/feature-status.md)
> 与 [未完成分析能力与技术债](docs/pending-capabilities.md)。

| 模块 | 能力数 | 已实现 |
|---|---|---|
| 基础分析 `basic` | 13 | ✅ 13 |
| 高级分析 `advanced` | 8 | ✅ 8 |
| 安全分析 `security` | 5 | ✅ 5 |
| 动态分析 `dynamic` | 5 | ✅ 5 |
| AI 分析 `ai` | 8 | ✅ 0 |
| 自动化 `automation` | 7 | ✅ 5 |
| **合计** | **46** | **✅ 36** |

### 基础分析 `basic`（13/13）

- [x] `basic.file` — 文件属性、SHA-256、Magic 与格式识别
- [x] `basic.elf` — ELF 类、字节序、类型、机器、入口与段表
- [x] `basic.symbols` — `.dynsym`/`.symtab` 导出枚举 + Itanium C++ demangle + JNI 签名恢复
- [x] `basic.dwarf` — DWARF 2-5 参数名/参数类型/返回类型/声明位置，渲染层与 `basic.symbols` 联合
- [x] `basic.types` — ELF+DWARF 合并恢复函数签名、全局变量与 class/struct/union/enum 复合类型
- [x] `basic.cpp` — RTTI/vtable/typeinfo + 构造析构克隆码 + 虚方法/继承（DWARF 基类与 RTTI 互证）
- [x] `basic.dynamic` — 动态链接事实（`DT_NEEDED`/SONAME/RPATH/RUNPATH、构造析构入口、符号版本、重定位与导入计数）
- [x] `basic.disasm` — Capstone 指令解码 + 函数边界恢复（符号优先，x86-64/AArch64 序言扫描补齐）
- [x] `basic.cfg` — leader 切分基本块、边分类与回边环检测，间接目标不猜测
- [x] `basic.callgraph` — 调用点解析 local/import/indirect，PLT 桩经 `.rela.*` 恢复导入符号名，含 `callers_of`
- [x] `basic.dataflow` — 函数内 use-def + 跨块到达定义，声明为 `scope: intra-procedural`；另含**参数可控性（污点）**事实（以 ABI 传参寄存器为源，栈/帧指针不算参数），并按**污点函数库**识别 source/sink 调用
- [x] `basic.xref` — 指令操作数到字符串字面量的交叉引用（x86/x86-64/AArch64/ARM）
- [x] `basic.jni` — 静态 `Java_*` 导出 + 动态 `RegisterNatives` 表，strip 后降级为地址

### 高级分析 `advanced`（8/8）

- [x] `advanced.strings` — 纯 Python 可见串提取与去重，分类 URL/敏感/Base64，并归属 ELF 分节
- [x] `advanced.constants` — 已知算法常量表扫描（AES/MD5/SHA/CRC32/zlib/Base64/ChaCha20）
- [x] `advanced.algorithm` — 常量表 + 符号名 + 字符串线索交叉判定，多源标 `corroborated`
- [x] `advanced.protocol` — 协议特征与网络 import 交叉识别 21 个协议指纹
- [x] `advanced.file-format` — 外层与内嵌格式魔数扫描 + 结构校验 `verified`
- [x] `advanced.library` — `DT_NEEDED`/SONAME/符号前缀/版本串交叉识别 23 个库指纹
- [x] `advanced.compiler` — `.comment`/note 横幅 + 符号佐证，提取版本号与 build-id
- [x] `advanced.obfuscation` — 加壳/混淆签名、OLLVM 符号、分节熵阈值 + **控制流平坦化判定**（依据 `basic.cfg` 中「以间接跳转结束的基本块占比」，即状态机经调度表转移的形态）

### 安全分析 `security`（5/5）

- [x] `security.hardening` — PIE/NX/RELRO + 栈保护(Canary)/CFI/AArch64 PAC
- [x] `security.dangerous-api` — 符号名精确匹配危险 API（FORTIFY 归一化 + 严重度阈值），计划内带调用点证据
- [x] `security.vulnerability` — 危险 API 命中映射到 CWE 并生成漏洞模式 Finding，置信度 MEDIUM；**有污点证据时标记 `parameter_controllable`**，并为「污点到达的 sink」单独生成 Finding（携带 source→caller→sink 的完整链路）
- [x] `security.risk` — hardening/dangerous-api/strings 三源聚合去重 + 风险分档
- [x] `security.dynamic-loading` — 继承 RPATH、可写搜索路径、`DT_TEXTREL`、`DF_SYMBOLIC`
- [x] 内置 Rule — `security.sensitive-string` / `security.hardcoded-url` / `security.encoded-payload`

### 动态分析 `dynamic`（5/5）

- [x] `dynamic.trace` — 授权门 → 沙箱探测 → dry-run 计划判定链；默认拒绝执行、不启动进程、不采集事件
- [x] `dynamic.arguments` — 参数采集：候选入口与采样点 + 沙箱化驱动计划 + `dlopen` harness 源码
- [x] `dynamic.memory` — 内存观测：映射/堆/栈观测白名单 + 沙箱化驱动计划
- [x] `dynamic.syscalls` — 系统调用拦截：默认拒绝的 seccomp 过滤策略 + 重点关注 API
- [x] `dynamic.coverage` — 覆盖率采集：与 `basic.cfg` 基本块对齐的覆盖点索引

> 动态族全部是**计划版**：授权门（默认拒绝 + `allow_targets` 白名单）、沙箱探测（bwrap/firejail/docker/unshare）
> 与计划/执行分离都已落地，但**不启动任何进程、不采集真实事件**，真实事件流仍需外部采集器。

### AI 分析 `ai`（0/8）

> AI 族整体不实现：需要 Provider 抽象（本地优先策略）、隐私防护、证据引用与成本治理，
> 目前刻意不落地。

- [ ] `ai.function-name`
- [ ] `ai.parameter-semantics`
- [ ] `ai.struct-recovery`
- [ ] `ai.module-identification`
- [ ] `ai.algorithm-explanation`
- [ ] `ai.protocol-explanation`
- [ ] `ai.vulnerability-explanation`
- [ ] `ai.assembly-explanation`

### 自动化 `automation`（5/7）

- [x] `automation.binary-diff` — `diff OLD NEW` 符号级差异，`default_enabled=False`
- [x] `automation.fuzz-target` — 静态 Fuzz 入口识别 + 参数形状归类，标 `heuristic`
- [x] `automation.harness` — 模板型 libFuzzer 骨架生成，只产源码不执行
- [x] `automation.seed` — 由格式/协议/常量事实生成种子语料（定向种子 + 通用种子兜底），可选归档
- [x] `automation.report` — 汇总本次运行结果为 Text/JSON/Markdown/HTML/SARIF 报告（含规则引擎与分析器两侧的发现项），可选归档
- [ ] `automation.crash-cluster`
- [ ] `automation.workflow`

### 框架层

- [x] 六大模块目录与 `<module>.<capability>` 命名空间
- [x] 领域 CLI 命令树、`modules list/show`、`scan --module/--module-available`
- [x] **多目标扫描与目录批量展开**（`scan` 接受多个路径/目录，`--include`/`--exclude` 过滤，逐目标基线与门禁；**Web 控制台同样支持目录批量**）
- [x] YAML 配置体系（Schema、`config create/list/show/validate/use/set/unset`）
- [x] Analyzer/Rule/Profile/Renderer SDK 与依赖 DAG + stage 并发 Scheduler
- [x] 运行时控制：超时看门狗、SIGINT 取消令牌、进度观察者
- [x] Target/Result/Finding/Diagnostic 统一模型
- [x] 文件缓存（代码指纹/目标 sha256/analyzer 版本三层命中）
- [x] Text/JSON/Markdown/HTML/SARIF 输出
- [x] entry point 插件自动发现
- [x] CI Gate（`--fail-on`）与基线抑制（`--baseline`/`--update-baseline`）
- [x] 控制流平坦化判定（基于 CFG 图形态）
- [x] 参数可控性（污点）分析，函数内传播 + source→sink 跨函数链路
- [x] **外部可配置的污点函数库**（`configs/taint-functions.yaml`，支持 `--taint-library` 替换）
- [x] 动态采集器计划与 `dlopen` harness 模板（五项动态能力共用同一底座）
- [ ] 机器可校验的报告 JSON Schema
- [ ] 外部插件兼容协议
- [ ] 跨阶段并行资源预算
- [ ] License、CI、V1/V2 Golden 回归

### 污点函数库（source / sink）

污点分析用一张**函数表**判断「数据从哪来」与「数据流到哪去」。表是数据不是代码，
因此可以整份替换：

```bash
# 内置表（默认）：configs/taint-functions.yaml
PYTHONPATH=src python3 -m soinsight scan libfoo.so \
    --enable basic.symbols --enable basic.callgraph --enable basic.dataflow \
    --enable security.vulnerability --taint-library configs/taint-functions.yaml

# 项目自己的表
PYTHONPATH=src python3 -m soinsight scan libfoo.so --taint-library my-taint.yaml
```

表文件格式（YAML）：

```yaml
version: 1
sources:
  - name: recv          # 报告里显示的标识
    match: ^recv(@|$)   # 匹配链接名（mangled symbol）的正则
    kind: return        # return | argument | argument_any
    cwe: CWE-20
    description: 从套接字读取字节。
sinks:
  - name: system
    match: ^system(@|$)
    kind: argument
    argument: 0          # 第几个参数带污点（0 起）
    severity: critical
    cwe: CWE-78
```

`match_demangled: true` 让正则匹配 demangle 后的名字。`propagators` 段落描述「把污点从
第 N 个参数复制到第 M 个参数」的函数（如 `strcpy`）。文件缺失或格式错误只产生一条
`DATAFLOW_TAINT_LIBRARY_INVALID` 警告，其余分析照常进行。

检出结果形如 `getenv() -> lprofGetPathPrefix() -> strlen()`，并带上调用点、寄存器、
CWE 与严重度。置信度仍为 MEDIUM——链路证明的是数据来源，不是可利用性。

### 如何核验

```bash
PYTHONPATH=src python3 -m soinsight modules list                      # 已实现/外壳一目了然
PYTHONPATH=src python3 -m soinsight dynamic arguments libfoo.so       # 计划版：默认拒绝执行
PYTHONPATH=src python3 -m soinsight automation report libfoo.so       # 多格式报告
PYTHONPATH=src python3 -m soinsight automation seed libfoo.so         # 种子语料
PYTHONPATH=src python3 -m soinsight scan libs/ --include '*.so'       # 目录批量扫描
PYTHONPATH=src python3 -m soinsight scan libfoo.so --module-available basic,security,advanced
```

> **改动分析器逻辑后请带 `--no-cache` 复核。** 运行缓存按「代码指纹 + 目标 sha256 + 分析器版本」分键，
> 代码指纹覆盖包内所有 `.py`，因此正常改代码会自动失效；但同一进程内指纹只算一次，
> 手工连续验证时容易读到旧条目。用 `soinsight cache prune` 清理旧版本条目。

### 本轮实现的核实结论（2026-11-09）

清单不是按代码写的，而是逐项在**真实样本**（`in/libtest_demo.so`）上跑出来的。`in/` 被 `.gitignore` 排除，新克隆里样本缺失；运行 `python3 scripts/fetch_samples.py`（Windows 用 `py -3 scripts/fetch_samples.py`）下载并校验，或自行放一个真实 `.so` 到该路径。详见 [快速使用 · 获取验证样本](docs/quickstart.md)：

| 核实项 | 方式 | 结论 |
|---|---|---|
| 实现计数 | 重算注册表与能力目录 | 36/46，AI 族 8 项 + `automation.crash-cluster`/`workflow` 仅有外壳 |
| 控制流平坦化 | 真实 CFG 构建 + 真实库回归 | 真实未混淆库 124 个函数**零误报** |
| 参数可控性 | 与调用图做地址交叉验证 | 危险 API 的调用点地址在调用图与污点事实中一致 |
| 动态族安全性 | 替换 `subprocess` 为探针 | 授权后仍**零次**子进程调用，`executed` 全为 false |
| 多目标扫描 | 真实目录与多文件 | 目标数正确、逐目标成文、失败聚合 |
| 报告 | CLI | 汇总先运行的全部分析器，5 种格式齐备 |
| 种子 | CLI | 按事实分类、内容哈希去重 |

核实过程中修掉了三个真实缺陷，都属于「单测通过但功能是死的」：

1. **平坦化检测在真实二进制上从不生效**——原判据要求基本块出度 ≥ 4，而恢复出的基本块最多 2 个后继，
   该条件永远不可能满足；单测喂的是手工构造的字典，所以测试通过而功能失效。
   现改为以「以间接跳转结束的基本块占比」为判据。
2. **改判据后误报 19/124**——普通代码的返回点与 switch 同样是高入度汇合点。
   现只用间接跳转占比，普通代码误报归零。
3. **污点把 `rsp`/`rbp` 当成参数源**——寄存器折叠让 64 位的栈/帧指针与 32 位同名；
   且解码器对两种位宽都报 `x86`，现按位宽选择参数寄存器。

端到端回归在 `tests/integration/test_implemented_capabilities.py`，全部基于真实样本而非合成夹具。

## 开发原则

- 产品和文档先按六大能力域表达，技术组件下沉；
- 能力 ID 使用 `<module>.<capability>` 命名空间；
- 跨域协作通过声明式 DAG 和统一结果，不直接调用另一个模块实现；
- 默认不执行被分析文件，动态分析必须显式授权并隔离；
- 结构化结果优先，终端展示由 Renderer 负责；
- V1 在 V2 真实能力达到验收标准前继续保留。

## License

项目当前尚未提供 License 文件；公开分发前需要补齐许可证。
