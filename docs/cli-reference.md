# SOInsight V2 CLI 命令参考

## 1. 主命令树

```text
soinsight
├── scan
├── basic
├── advanced
├── security
├── dynamic
├── ai
├── automation
├── modules
├── report
├── plugins
├── doctor
├── cache
└── config
```

当前版本：`2.0.0.dev0`。

## 2. 产品领域命令

### 基础分析

```text
soinsight basic {file|elf|symbols|dwarf|types|cpp|disasm|cfg|callgraph|dataflow} TARGET [OPTIONS]
```

### 高级分析

```text
soinsight advanced {strings|constants|algorithm|protocol|file-format|library|compiler|obfuscation} TARGET [OPTIONS]
```

### 安全分析

```text
soinsight security {hardening|dangerous-api|vulnerability|risk} TARGET [OPTIONS]
```

### 动态分析

```text
soinsight dynamic {trace|arguments|memory|syscalls|coverage} TARGET [OPTIONS]
```

### AI 分析

```text
soinsight ai {function-name|parameter-semantics|struct-recovery|module-identification|algorithm-explanation|protocol-explanation|vulnerability-explanation|assembly-explanation} TARGET [OPTIONS]
```

### 自动化

```text
soinsight automation binary-diff OLD NEW
soinsight automation {fuzz-target|harness|seed|crash-cluster|report|workflow} TARGET [OPTIONS]
```

单目标命令已经接入 Runtime，但具体 Analyzer 尚未实现，因此目前通常返回 `ANALYSIS_PLAN_ERROR` 和退出码 3。`binary-diff` 是双目标保留外壳，目前直接返回退出码 3。

## 3. Runtime 通用参数

适用于 `scan` 和单目标领域能力：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `--config NAME_OR_PATH` | 活动配置/无 | 使用托管名称或外部 YAML |
| `--format {text,json}` | YAML/`text` | 输出格式 |
| `-o, --output PATH` | stdout | 输出文件，`-` 表示 stdout |
| `-j, --jobs N` | `1` | 预留并发配置，当前仍串行 |
| `--timeout SECONDS` | `60` | 超时配置 |
| `-q, --quiet` | false | 静默配置入口 |
| `-v, --verbose` | false | 详细配置入口 |
| `--no-color` | false | 禁用颜色配置入口 |
| `--no-cache` | false | 禁用缓存配置入口，Runtime 缓存尚未接入 |
| `--cache-dir PATH` | `.soinsight/cache` | 缓存目录 |
| `--fail-fast` | false | 快速失败配置 |

## 4. `scan`

```text
soinsight scan TARGET [--config NAME_OR_PATH] [--module IDS] [--enable IDS] [--profile ID] [OPTIONS]
```

- `--module basic,security`：展开产品模块内与当前单目标 Runtime 兼容的能力 ID；
- `--enable basic.elf,security.hardening`：精确选择 namespaced Analyzer ID；
- `--profile quick`：使用已注册 Profile；当前没有内置 Profile；
- `--config quick-security`：加载托管 YAML 名称或外部路径；未指定时加载活动配置；
- YAML 选择与 CLI `--module`/`--enable` 合并、去重，再应用 YAML `exclude`；
- 没有 YAML/CLI/Profile 选择项时使用 Registry 中默认启用的 Analyzer。

```bash
soinsight scan libfoo.so --module basic,security --format json
soinsight scan libfoo.so --enable basic.file,basic.elf -o result.json
```

当前没有内置 Analyzer。无选择时会产生 `NO_ANALYZERS_SELECTED`；选择模块时会因能力 Analyzer 尚未注册而产生 `ANALYSIS_PLAN_ERROR`。

## 5. `modules`

产品模块目录：

```bash
soinsight modules list
soinsight modules list --format json
soinsight modules show basic
soinsight modules show security --format json
```

`modules` 展示产品能力；它不等同于 `plugins`。

## 6. `plugins`

技术扩展注册表：

```bash
soinsight plugins list
soinsight plugins list --format json
```

它展示当前进程真正注册的 Analyzer。模块目录可以有 42 项能力，而已注册 Analyzer 仍为 0。

## 7. 配置与其他技术命令

YAML 配置管理：

```bash
soinsight config [--config-dir PATH] create NAME [--force]
soinsight config [--config-dir PATH] list [--format text|json]
soinsight config [--config-dir PATH] show NAME_OR_PATH
soinsight config [--config-dir PATH] validate NAME_OR_PATH
soinsight config [--config-dir PATH] use NAME_OR_PATH
soinsight config [--config-dir PATH] current
soinsight config [--config-dir PATH] clear
soinsight config [--config-dir PATH] set NAME_OR_PATH KEY YAML_VALUE
soinsight config [--config-dir PATH] unset NAME_OR_PATH KEY
```

示例：

```bash
soinsight config create quick
soinsight config set quick analysis.modules.basic '[file, elf]'
soinsight config set quick runtime.jobs 4
soinsight config set quick capability_options.advanced.strings.min_length 6
soinsight config use quick
soinsight scan libfoo.so
```

托管目录优先使用 `--config-dir`，其次是 `SOINSIGHT_CONFIG_DIR`，最后是 `~/.config/soinsight/configs`。Schema、优先级与字段说明见 [YAML 配置指南](configuration.md)。

其他技术命令：

```bash
soinsight doctor [--format text|json]
soinsight report INPUT [--format text|json] [-o OUTPUT]
soinsight cache [info] [--cache-dir PATH]
```

- `doctor`：显示版本、Python、六大产品模块数量、Analyzer 数量和 V1 外部工具；
- `report`：当前只读取并重新格式化合法 JSON；
- `cache info`：当前只显示缓存路径。

## 8. 兼容别名

开发期保留隐藏别名：`file`、`elf`、`symbols`、`strings`、`dwarf`、`disasm`、`cfg`、`callgraph`、`diff`。例如 `soinsight elf x.so` 会映射到 `basic.elf`。

这些别名不出现在主帮助中，也不作为稳定公开命令；新脚本应使用领域命令。

## 9. 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 命令或扫描框架成功 |
| `2` | 参数、目标、配置、模块 ID 或报告输入错误 |
| `3` | 分析计划错误、Analyzer 缺失或能力尚未实现 |
| `4` | Runtime 整体 `failed` |
| `5` | Runtime 整体 `partial` |

风险阈值退出码尚未实现。
