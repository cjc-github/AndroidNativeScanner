# SOInsight CLI 输出规范

## 1. 目标

SOInsight CLI 输出同时服务两类用户：

- 人类用户：需要快速理解命令能做什么、当前能力是否已实现、失败后下一步怎么处理；
- 自动化脚本：需要稳定 JSON、稳定退出码、无颜色污染和可解析字段。

本规范定义 `text`、`json` 和 `quiet` 三类输出契约，并优先解决产品能力目录与实际 Analyzer 注册状态容易混淆的问题。

## 2. 通用原则

1. **人类输出优先可读**：`text` 输出使用分组、固定列宽、状态列和下一步提示，不使用 tab 对齐。
2. **机器输出保持稳定**：`json` 输出保持结构化字段，字段命名使用 snake_case，不携带 ANSI 颜色。
3. **状态必须显式**：能力目录中存在的 capability 不代表已实现，文本输出必须展示 `implemented`、`partial`、`planned` 或 `catalog-only`。
4. **错误必须可操作**：错误输出必须包含发生了什么、原因、建议命令和稳定退出码。
5. **颜色可选**：未来仅在 TTY 下启用颜色；`--no-color` 和 JSON 输出必须禁用颜色。
6. **中文显示宽度按双宽处理**：所有对齐逻辑必须考虑中英文混排。

## 3. 输出模式

| 模式 | 目标 | 约束 |
|---|---|---|
| `text` | 给人看 | 分组、对齐、状态、提示 |
| `json` | 给机器看 | 稳定 schema、无颜色、可解析 |
| `quiet` | 给 CI/脚本 | 成功尽量少输出，失败输出简明错误摘要 |

当前阶段优先实现 `text` 输出改进；`json` schema 保持兼容；`quiet` 行为后续补齐。

## 4. 主帮助输出

`soinsight --help` 应按命令用途分组，而不是只使用 argparse 默认列表。

目标形态：

```text
SOInsight 2.0.0.dev0
Linux/Android ELF analysis toolbox

Usage:
  soinsight <command> [options]

Analysis domains:
  basic       Basic file, ELF, symbol and code-structure analysis
  advanced    Strings, constants, compiler and obfuscation analysis
  security    Hardening, dangerous API and vulnerability analysis
  dynamic     Authorized runtime tracing and coverage
  ai          Evidence-based AI assistance
  automation  Diff, fuzzing, reports and workflow automation

Project commands:
  scan        Run a composed analysis plan
  modules     Inspect product capability catalog
  plugins     Inspect registered analyzers
  config      Manage YAML analysis configurations
  doctor      Inspect local environment
  report      Validate or display JSON result
  cache       Inspect cache location

Use:
  soinsight <command> --help
```

## 5. `modules list`

`modules list` 展示产品能力目录，并必须说明每个模块当前实现状态。

目标形态：

```text
MODULE      NAME      CAPABILITIES  STATUS
basic       基础分析            10  partial
advanced    高级分析             8  catalog-only
security    安全分析             4  catalog-only
dynamic     动态分析             5  catalog-only
ai          AI 分析              8  catalog-only
automation  自动化               7  catalog-only
```

状态定义：

| 状态 | 含义 |
|---|---|
| `implemented` | 模块内所有单目标 capability 都有已注册 Analyzer |
| `partial` | 模块内至少一个 capability 已实现，但不是全部 |
| `catalog-only` | 模块只存在于产品目录，尚无已注册 Analyzer |

## 6. `modules show <module>`

`modules show` 应回答：模块是什么、当前整体状态是什么、每项 capability 是否能执行。

目标形态：

```text
Module: basic
Name:   基础分析
Status: partial

Description:
  建立二进制、ELF、代码结构和统一 IR 的基础事实。

Capabilities:
  COMMAND     ID                NAME             STATUS
  file        basic.file        文件分析          implemented
  elf         basic.elf         ELF 解析          planned
  symbols     basic.symbols     Symbol 解析      planned
```

capability 状态定义：

| 状态 | 含义 |
|---|---|
| `implemented` | 对应 Analyzer 已注册，可通过领域命令或 scan 执行 |
| `planned` | capability 在产品目录中，但 Analyzer 尚未注册 |

## 7. `plugins list`

`plugins list` 展示实际注册的技术 Analyzer。它和 `modules` 的产品目录不同。

目标形态：

```text
ID          VERSION  KIND       DEFAULT  NAME
basic.file  1.0.0    collector  yes      File Analyzer
```

无 Analyzer 时：

```text
No analyzers registered.

Product capabilities may still appear under `soinsight modules`.
Use `soinsight modules list` to inspect the catalog.
```

## 8. `doctor`

`doctor` 应采用健康检查输出，包含核心环境、能力状态、外部工具和总体状态。

目标形态：

```text
SOInsight doctor

Core:
  Version               2.0.0.dev0
  Python                3.10.12
  Executable            /path/to/python

Capabilities:
  Product modules        6
  Registered analyzers   1

External tools:
  readelf               ok       /usr/bin/readelf
  nm                    ok       /usr/bin/nm
  strings               ok       /usr/bin/strings

Status:
  ok
```

缺失外部工具时：

```text
External tools:
  readelf               missing

Hint:
  Install binutils: sudo apt-get install binutils
```

## 9. 分析结果文本输出

`text` 分析结果应面向人类，而不是直接暴露内部框架字段。

目标形态：

```text
Target:
  Path       README.md
  Size       6.2 KB
  SHA-256    abc...

Analysis:
  basic.file  success  0 ms

File facts:
  Format      unknown
  Magic       2320534f496e7369
  Name        README.md

Findings:
  none
```

JSON 输出继续保持当前结构化 `ApplicationResponse` / `ScanResult` / `AnalysisResult` 模型。

## 10. 错误输出

错误输出必须让用户知道下一步怎么做。

目标形态：

```text
Error: capability is not implemented

Capability:
  basic.elf

Reason:
  Analyzer not found: basic.elf

Try:
  soinsight modules show basic
  soinsight basic file <target>

Exit code: 3
```

常见错误映射：

| 诊断码 | 标题 | 建议 |
|---|---|---|
| `ANALYSIS_PLAN_ERROR` | capability is not implemented 或 analysis plan failed | 查看 `modules show` 或选择已实现 capability |
| `INVALID_TARGET` | invalid target | 检查路径是否存在且为文件 |
| `INVALID_ANALYSIS_CONFIG` | invalid analysis config | 执行 `soinsight config validate <name-or-path>` |
| `NO_ANALYZERS_SELECTED` | no analyzers selected | 使用 `--module`、`--enable` 或配置文件选择能力 |

## 11. 实施优先级

### P0：避免误导用户

优先实现：

1. `modules list` 增加 `STATUS`；
2. `modules show` 增加模块状态和 capability 状态；
3. `plugins list` 表格化；
4. 未实现能力错误输出增加 `Try:` 建议。

### P1：提升可读性

后续实现：

1. 主 help 分组；
2. `doctor` 分组；
3. 分析结果 text renderer 分块输出。

### P2：终端体验

已实现：

1. TTY 颜色；
2. `quiet` 模式；
3. 终端宽度适配；
4. 输出 schema 文档化（见 [CLI 输出 Schema](cli-output-schema.md)）。

## 12. 测试要求

每类文本输出必须有集成测试锁定：

- `modules list` 对齐、状态列和状态值；
- `modules show basic` 的模块状态、capability 状态；
- `plugins list` 表头和 analyzer 行；
- 未注册 Analyzer 的错误摘要和 `Try:` 建议；
- JSON 输出不受文本格式调整影响。

测试必须通过真实 CLI `main()` 调用，不通过 mock 验证格式。
