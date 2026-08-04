# SOInsight / Android Native Scanner

SOInsight 是一个面向 Linux/Android ELF 动态库（主要为 `.so` 文件）的本地分析工具项目。

仓库当前同时保留两个版本：

- **V1（可用功能）**：现有 Android Native Scanner，使用 `python3 main.py` 运行；
- **V2（框架阶段）**：模块化 CLI 工具箱，使用 `soinsight` 或 `python3 -m soinsight` 运行。

> 截至 2026-08-04，V2 已完成外部框架骨架，但尚未迁移具体 ELF 分析器。执行 V2 `scan` 时如果没有注册 Analyzer，会返回 `NO_ANALYZERS_SELECTED`，这是当前阶段的预期行为。

## 文档导航

| 文档 | 内容 |
|---|---|
| [快速开始](docs/getting-started.md) | 环境要求、安装、V1/V2 首次运行 |
| [V2 使用手册](docs/user-guide.md) | 扫描、输出、诊断、常见问题 |
| [V2 CLI 命令参考](docs/cli-reference.md) | 当前命令、参数、退出码和实现状态 |
| [V2 架构说明](docs/architecture.md) | 分层结构、运行链路、扩展边界 |
| [Analyzer 与 Rule 开发指南](docs/extension-development.md) | 新增分析器、规则、Profile 和 Renderer |
| [V1 到 V2 迁移指南](docs/migration-v1-to-v2.md) | 迁移原则、映射和推荐顺序 |
| [项目状态与路线图](docs/project-status.md) | 已完成、未实现、下一阶段验收标准 |
| [V2 总体设计](design/SOInsight_V2.0_Software_Design_Specification.md) | V2 主设计和长期规划 |
| [V1 深度分析规划](design/SOInsight_Deep_SO_Analysis_Plan_V1.0.md) | 历史规划，仅供参考 |

## 快速运行

### V2：开发模式

```bash
PYTHONPATH=src python3 -m soinsight --help
PYTHONPATH=src python3 -m soinsight doctor
PYTHONPATH=src python3 -m soinsight plugins list
PYTHONPATH=src python3 -m soinsight scan README.md --format json
```

### V2：可编辑安装

要求 Python 3.10 或更高版本：

```bash
python3 -m pip install -e .
soinsight --version
soinsight doctor
```

安装开发依赖并运行测试：

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

构建可安装的 CLI Wheel：

```bash
./scripts/build_cli.sh
python3 -m pip install --force-reinstall dist/soinsight-*.whl
soinsight --help
```

也可以构建后直接安装到当前 Python 环境：

```bash
./scripts/build_cli.sh --install
```

### V1：运行现有扫描功能

V1 依赖系统中的 `readelf`、`nm` 和 `strings`，通常由 `binutils` 提供：

```bash
python3 main.py libexample.so
python3 main.py ./lib/
```

`termcolor` 是 V1 的可选依赖：

```bash
python3 -m pip install -e '.[legacy]'
```

## 当前仓库结构

```text
AndroidNativeScanner/
├── main.py                    # V1 入口
├── src/
│   ├── analyzer/              # V1 具体分析器
│   ├── cli.py                 # V1 CLI
│   └── soinsight/             # V2 模块化工具箱
│       ├── cli/               # CLI 适配层
│       ├── application/       # 应用服务层
│       ├── core/              # 模型、Analyzer、Rule、Runtime
│       ├── analyzers/         # V2 内置分析器注册位置
│       ├── renderers/         # text/json 输出
│       ├── infrastructure/    # 配置、工具、存储、插件边界
│       └── compatibility/     # V1 兼容适配预留
├── tests/                     # V2 单元与集成测试
├── scripts/build_cli.sh       # 构建并校验 V2 CLI Wheel
├── docs/                      # 使用和开发文档
└── design/                    # 总体设计与历史规划
```

## V1 当前能力

V1 当前包含：

- ELF Header 基础信息；
- 导出符号和危险函数检测；
- 字符串提取与统计；
- URL、敏感信息、Base64 数据检测；
- JNI 符号分析；
- 单文件和目录扫描；
- 文本报告及风险汇总。

V1 的扩展方式仍然是继承 `src/analyzer/base.py` 中的 `BaseAnalyzer` 并注册到 `AnalysisCoordinator`。新能力原则上应优先面向 V2 Analyzer SDK 开发；需要复用 V1 时，通过兼容适配层逐步迁移。

## V2 当前能力

V2 已实现：

- `soinsight` 命令树；
- `AnalysisTarget`、`AnalysisResult`、`ScanResult`、`Finding` 和 `Diagnostic`；
- Analyzer、Rule、Profile、Renderer 注册机制；
- Analyzer 依赖 DAG 规划和循环检测；
- 串行 Scheduler、失败隔离和依赖跳过；
- Text/JSON Renderer；
- 外部工具调用和 Artifact Store 基础边界；
- Python 包安装、Wheel 构建；
- 框架单元测试和 CLI 集成测试。

V2 当前尚未实现：

- 具体 `file`、`elf`、`symbols`、`strings`、`security` Analyzer；
- Runtime 缓存读写；
- 并发 Scheduler；
- 外部插件自动发现；
- Markdown/HTML/SARIF 报告；
- 目录递归扫描；
- DWARF、反汇编、CFG、Diff、动态分析、Fuzz 和 AI 实际功能。

详细状态参见[项目状态与路线图](docs/project-status.md)。

## 开发原则

- 默认不执行被分析文件；
- Analyzer 返回结构化数据，不直接负责终端输出；
- 安全判断优先放在 Rule 中，基础事实提取放在 Analyzer 中；
- Analyzer 通过 `requires` 声明依赖，不在内部主动调度其他 Analyzer；
- V2 输出协议通过 Schema 版本字段演进；
- V1 在迁移完成前保持可用，不直接替换其入口。

## License

仓库当前未声明独立 License 文件。对外发布或引入第三方依赖前，应先补充许可证和依赖合规策略。
