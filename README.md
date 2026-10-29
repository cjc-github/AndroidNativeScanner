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

> 截至 2026-10-29，六大模块目录、40 项原始能力、2 项自动化增强能力以及为动态链接与交叉引用新增的 3 项能力（`basic.dynamic`、`basic.xref`、`security.dynamic-loading`）的命令外壳已经建立（advanced 八项能力已全部落地），`basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`basic.types`、`basic.cpp`、`basic.disasm`、`basic.cfg`、`basic.callgraph`、`basic.dataflow`、`basic.dynamic`、`basic.xref`、`advanced.strings`、`advanced.constants`、`advanced.algorithm`、`security.hardening`、`security.dangerous-api`、`security.vulnerability`、`security.risk`、`security.dynamic-loading` Analyzer（外加三条内置安全规则）已实现；其余 Analyzer 尚未迁移。未实现的领域命令返回 `ANALYSIS_PLAN_ERROR`，这是当前框架阶段的预期行为。

## 文档导航

| 文档 | 内容 |
|---|---|
| [快速使用](docs/quickstart.md) | 安装、最常用命令和输出选项（一页） |
| [模块体系](docs/module-system.md) | 六大产品模块、45 项能力及跨域依赖规则 |
| [项目状态与路线图](docs/project-status.md) | 已完成、未实现和下一阶段验收标准 |
| [架构说明](docs/architecture.md) | 产品能力层与技术实现层的关系 |
| [扩展开发指南](docs/extension-development.md) | 为能力实现 Analyzer、Rule、Profile、Renderer |
| [V1 到 V2 迁移](docs/migration-v1-to-v2.md) | 迁移原则、领域映射和顺序 |
| [详细使用文档归档](docs/archive/) | 原快速开始/使用手册/CLI 命令参考/YAML 配置指南 |
| [V2 软件设计说明书](design/design_v2.0.md) | 六大能力域、CLI、设计模式与详细架构的唯一主设计 |
| [V3 设计占位](design/design_v3.0.md) | V3 尚未启动及其启动条件 |
| [V1 历史规划](design/design_v1.0.md) | 历史参考 |

## 快速运行

```bash
# 无安装运行
PYTHONPATH=src python3 -m soinsight --help
PYTHONPATH=src python3 -m soinsight modules list
PYTHONPATH=src python3 -m soinsight modules show basic
PYTHONPATH=src python3 -m soinsight doctor

# 领域命令（basic.file/basic.elf/basic.symbols/basic.dwarf/basic.types/basic.cpp/advanced.strings/security.hardening/security.dangerous-api/security.vulnerability/security.risk 已实现；其余为能力外壳）
PYTHONPATH=src python3 -m soinsight basic elf README.md --format json
PYTHONPATH=src python3 -m soinsight basic symbols libfoo.so
PYTHONPATH=src python3 -m soinsight basic dwarf libfoo.so --format json
PYTHONPATH=src python3 -m soinsight advanced strings libfoo.so
PYTHONPATH=src python3 -m soinsight security hardening README.md
PYTHONPATH=src python3 -m soinsight security dangerous-api libfoo.so
PYTHONPATH=src python3 -m soinsight security risk libfoo.so --format json

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
# Windows：双击 web\start-web.bat，或
py -3 web/server.py                  # 推荐 py -3：默认 python 可能是没装 PyYAML 的版本
# Linux / macOS
python3 web/server.py

python3 web/server.py --port 9000    # 指定端口（默认 8765，被占用则顺延）
python3 web/server.py --no-open      # 不自动打开浏览器
python3 web/server.py --timeout 600  # 单次分析超时（默认 180 秒）
```

- 支持拖拽上传、服务器绝对路径、`in/` 目录样本三种目标来源；上传文件写入临时目录，分析后删除；
- 分析能力支持任意多选（依赖自动补齐），也可切到「组合扫描」跑全部已实现 Analyzer；
- 运行中可点「停止分析」终止子进程；结果可复制/下载 JSON，符号表与发现项可导出 CSV；
- `web/so-scan.html` 是单独的「深度分析台」：一键全量扫描 + 实时日志 + 结果摘要；
- 包内另有旧的 `soinsight web` 子命令（端口 8080，简易上传页），日常请使用 `web/server.py`。

## 当前仓库结构

```text
AndroidNativeScanner/
├── main.py                       # V1 入口
├── src/
│   ├── analyzer/                 # V1 具体分析器
│   ├── cli.py                    # V1 CLI
│   └── soinsight/                # V2 CLI 工具箱
│       ├── modules/              # 六大产品能力域及能力目录
│       │   ├── basic/
│       │   ├── advanced/
│       │   ├── security/
│       │   ├── dynamic/
│       │   ├── ai/
│       │   └── automation/
│       ├── cli/                  # CLI 适配层
│       ├── application/          # 应用服务层
│       ├── core/                 # Analyzer/Rule/Planner/Runtime 等共享机制
│       ├── analyzers/            # 具体 Analyzer 注册位置
│       ├── renderers/            # Text/JSON/Markdown/HTML/SARIF 输出
│       ├── infrastructure/       # 配置、工具、存储、插件边界
│       │   ├── elf/              # 纯 Python ELF 解析 + C++ demangle + JNI 解码
│       │   └── dwarf/            # 纯 Python DWARF 调试信息解析
│       └── compatibility/        # V1 兼容适配预留
├── tests/                        # V2 单元与集成测试
├── web/                          # 本地 Web 控制台：server.py / index.html / so-scan.html / start-web.bat
├── scripts/build_cli.sh          # Wheel 构建与入口校验
├── docs/                         # 使用与开发文档
└── design/                       # V2 主设计、V3 占位与 V1 历史规划
```

## 当前能力边界

V1 已具备 ELF Header、符号、字符串、URL/敏感信息/Base64/JNI 检测以及批量扫描等能力。

V2 已具备：

- 六大产品模块和能力目录；
- 领域化 CLI 命令树与 `modules` 查询命令；
- `scan --module` 跨域选择；
- YAML 配置 Schema、创建/查看/校验/激活/set/unset 管理及活动配置；
- YAML 模块/功能点选择、排除、runtime/output 和 capability options 合并；
- Analyzer/Rule/Profile/Renderer 扩展接口；
- Analyzer 依赖 DAG、stage 并发 Scheduler（`jobs > 1`）和失败隔离；
- Analyzer 超时看门狗、外部取消令牌和进度观察者；
- Target/Result/Finding/Diagnostic 统一模型；
- Text/JSON/Markdown/HTML/SARIF Renderer、ToolRunner、ArtifactStore 基础边界；
- Python 包安装和 Wheel 构建脚本。

V2 已实现 `basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`basic.types`、`basic.cpp`、`advanced.strings`、`security.hardening`、`security.dangerous-api`、`security.vulnerability`、`security.risk`：

- `basic.symbols` 枚举导出函数并恢复签名：`.dynsym`/`.symtab` 符号事实、Itanium C++ mangled name 解出的参数类型、JNI native 方法名解出的 Java 包名/类名/方法名与参数类型。demangler 已在 5 个真实 C++ 共享库（2943 个导出函数）上与参考实现全量比对：1895 个 C++ 符号全部解出，0 个无法解码、0 个类型差异；
- `basic.dwarf` 解析 DWARF 调试信息，补回参数名、参数类型、返回类型和声明位置，并在渲染层与 `basic.symbols` 按 mangled name 联合；
- `basic.types` 合并 ELF 符号表与 DWARF，恢复函数签名、全局变量及 class/struct/union/enum 复合类型（成员、基类、枚举值），stripped 时不猜测类型；
- `basic.cpp` 恢复 C++ 结构事实：RTTI/vtable/typeinfo 符号、构造/析构函数（C1-C5/D0-D5 克隆码全部支持）、虚方法与继承关系（DWARF 基类 + RTTI 符号双方印证）；只有定义符号才产生类证据，纯 C 结构不入类清单；
- `advanced.strings` 对任意文件做纯 Python 可见串提取与去重，分类 JSON/URL/硬编码密钥/Token/JWT 与可解码 Base64，并归属 ELF 分节；截断在数据与诊断中显式声明；
- `security.risk` 聚合 hardening/dangerous-api 发现项与字符串指标，按指纹去重计分并分档（权重可通过能力选项覆盖）；
- 三条内置规则 `security.sensitive-string` / `security.hardcoded-url` / `security.encoded-payload` 随规则引擎自动把字符串事实转为可复核的发现项。

V2 尚未具备其他具体业务 Analyzer（反汇编/CFG/Call Graph/Data Flow、动态/AI/Automation、高级分析其余能力）、外部插件协议、完整报告、目录扫描以及动态/AI/Fuzz 执行能力。详细状态见[项目状态与路线图](docs/project-status.md)与[未完成分析能力与技术债](docs/pending-capabilities.md)。

## 开发原则

- 产品和文档先按六大能力域表达，技术组件下沉；
- 能力 ID 使用 `<module>.<capability>` 命名空间；
- 跨域协作通过声明式 DAG 和统一结果，不直接调用另一个模块实现；
- 默认不执行被分析文件，动态分析必须显式授权并隔离；
- 结构化结果优先，终端展示由 Renderer 负责；
- V1 在 V2 真实能力达到验收标准前继续保留。

## License

项目当前尚未提供 License 文件；公开分发前需要补齐许可证。
