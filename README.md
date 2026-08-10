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

> 截至 2026-08-10，六大模块目录、40 项原始能力及 2 项自动化增强能力的命令外壳已经建立，`basic.file` Analyzer 已实现；ELF/安全/动态/AI 等其他 Analyzer 尚未迁移。未实现的领域命令返回 `ANALYSIS_PLAN_ERROR`，这是当前框架阶段的预期行为。

## 文档导航

| 文档 | 内容 |
|---|---|
| [快速开始](docs/getting-started.md) | 环境、安装、构建和首次运行 |
| [使用手册](docs/user-guide.md) | 六大模块、组合扫描、输出和诊断 |
| [YAML 配置指南](docs/configuration.md) | 模块/功能点订制、配置创建、激活和管理 |
| [CLI 命令参考](docs/cli-reference.md) | 当前命令树、参数、状态和退出码 |
| [模块体系](docs/module-system.md) | 六大产品模块、42 项能力及跨域依赖规则 |
| [架构说明](docs/architecture.md) | 产品能力层与技术实现层的关系 |
| [扩展开发指南](docs/extension-development.md) | 为能力实现 Analyzer、Rule、Profile、Renderer |
| [V1 到 V2 迁移](docs/migration-v1-to-v2.md) | 迁移原则、领域映射和顺序 |
| [项目状态与路线图](docs/project-status.md) | 已完成、未实现和下一阶段验收标准 |
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

# 领域命令（basic.file 已实现；其余为能力外壳）
PYTHONPATH=src python3 -m soinsight basic elf README.md --format json
PYTHONPATH=src python3 -m soinsight security hardening README.md

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
│       ├── renderers/            # Text/JSON 输出
│       ├── infrastructure/       # 配置、工具、存储、插件边界
│       └── compatibility/        # V1 兼容适配预留
├── tests/                        # V2 单元与集成测试
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
- Analyzer 依赖 DAG、串行 Scheduler 和失败隔离；
- Target/Result/Finding/Diagnostic 统一模型；
- Text/JSON Renderer、ToolRunner、ArtifactStore 基础边界；
- Python 包安装和 Wheel 构建脚本。

V2 已实现 `basic.file`，尚未具备其他具体业务 Analyzer、真实缓存、并发调度、外部插件发现、完整报告、目录扫描以及动态/AI/Fuzz 执行能力。详细状态见[项目状态与路线图](docs/project-status.md)。

## 开发原则

- 产品和文档先按六大能力域表达，技术组件下沉；
- 能力 ID 使用 `<module>.<capability>` 命名空间；
- 跨域协作通过声明式 DAG 和统一结果，不直接调用另一个模块实现；
- 默认不执行被分析文件，动态分析必须显式授权并隔离；
- 结构化结果优先，终端展示由 Renderer 负责；
- V1 在 V2 真实能力达到验收标准前继续保留。

## License

项目当前尚未提供 License 文件；公开分发前需要补齐许可证。
