# SOInsight V2 YAML 配置指南

SOInsight V2 使用 YAML 配置把“分析哪些模块/能力、怎样运行、怎样输出以及能力参数”保存为可复用策略。配置既可以由 CLI 管理，也可以作为普通文件放入项目并通过路径使用。

## 1. 完整结构

```yaml
schema_version: 1
name: quick-security
description: 快速基础与安全分析

analysis:
  modules:
    basic:
      - file
      - elf
      - symbols
    security:
      - hardening
  capabilities:
    - advanced.strings
  exclude:
    - basic.symbols
  # profile: quick

runtime:
  jobs: 4
  timeout_seconds: 120
  cache_enabled: true
  cache_dir: .soinsight/cache
  fail_fast: false
  quiet: false
  verbose: false
  no_color: false

output:
  format: json
  path: result.json

capability_options:
  advanced.strings:
    min_length: 6
  security.risk:
    threshold: high
```

`schema_version` 当前必须为 `1`。

## 2. 选择模块和功能点

`analysis.modules` 的键是六大产品模块：`basic`、`advanced`、`security`、`dynamic`、`ai`、`automation`。值是该模块内的 capability 命令名，而不是完整 ID：

```yaml
analysis:
  modules:
    basic: [file, elf]
    security: [hardening, risk]
```

使用带引号的 `"*"` 选择模块内所有适用于当前单目标 Runtime 的能力：

```yaml
analysis:
  modules:
    advanced: "*"
```

`analysis.capabilities` 使用完整 namespaced ID，可跨模块精确补充；`analysis.exclude` 最后应用，可排除由模块、Profile 或 CLI 合并得到的能力：

```yaml
analysis:
  capabilities: [advanced.strings, ai.summary]
  exclude: [advanced.strings]
```

当前 `scan` 只接受单目标，因此 `automation.binary-diff` 等多目标能力不能放进此配置。后续 Workflow 配置将负责多目标和多阶段编排。

## 3. 创建和管理

```bash
soinsight config create quick-security
soinsight config list
soinsight config show quick-security
soinsight config validate quick-security
soinsight config use quick-security
soinsight config current
soinsight config clear
```

默认托管目录为 `~/.config/soinsight/configs`。可以通过环境变量或管理命令参数改变：

```bash
export SOINSIGHT_CONFIG_DIR="$PWD/.soinsight-configs"
soinsight config --config-dir ./configs create team-security
```

活动配置指针保存在托管目录上一级的 `active-config`。`use` 既接受托管名称，也接受外部 `.yaml`/`.yml` 路径。

## 4. 修改配置

`set` 的值按 YAML 解析，因此数字、布尔、列表和映射无需专用参数：

```bash
soinsight config set quick-security analysis.modules.basic '[file, elf]'
soinsight config set quick-security analysis.modules.security '"*"'
soinsight config set quick-security runtime.jobs 4
soinsight config set quick-security output.format json
soinsight config set quick-security capability_options.advanced.strings.min_length 6
soinsight config unset quick-security output.path
```

每次修改都会先验证完整配置，再原子替换原文件。失败时原文件不变。CLI 管理写回会规范化 YAML，原注释不会保留；需要保留注释时可用编辑器修改后执行 `config validate`。

## 5. 用于扫描

显式使用：

```bash
soinsight scan libfoo.so --config quick-security
soinsight scan libfoo.so --config ./configs/team-security.yaml
```

设置活动配置后可省略 `--config`：

```bash
soinsight config use quick-security
soinsight scan libfoo.so
```

配置和 CLI 选择会合并：

```bash
soinsight scan libfoo.so --config quick-security \
  --module ai --enable advanced.entropy
```

对于显式领域命令，YAML 只复用 runtime、output 和 `capability_options`，不会扩大能力选择：

```bash
soinsight basic elf libfoo.so --config quick-security
# 始终只请求 basic.elf
```

## 6. 优先级和边界

当前执行优先级为：

```text
显式 CLI 参数 > 显式/活动 YAML 配置 > Runtime 默认值
```

- `--module`、`--enable` 与 YAML 选择合并并去重；
- YAML `analysis.exclude` 最后应用；
- `--format`、`--output`、`--jobs`、`--timeout`、`--cache-dir` 覆盖 YAML；
- CLI 布尔开关用于开启对应行为，`--no-cache` 明确关闭 YAML 缓存；
- 未传 `--config` 时自动加载活动配置；没有活动配置时保持原默认行为；
- `capability_options` 通过 `RuntimeConfig.extra` 传给 Analyzer，具体键由各能力定义和校验。

## 7. Profile、YAML Config 和 Workflow

- **Profile**：由产品/插件发布的稳定能力集合，回答“常用组合是什么”；
- **YAML Config**：用户可管理的分析策略，回答“这次/这个项目选择什么、怎样运行和输出”；
- **Workflow**：后续自动化编排，回答“多个目标、阶段、条件、基线和发布如何串联”。

三者不是互相替代：YAML 可以引用 Profile，Workflow 未来可以引用一个或多个 YAML 配置。

## 8. 安全建议

不要把 API Key、Token、密码直接写入并提交 YAML。AI Provider 等敏感凭据后续应通过环境变量、系统 Keyring 或 CI Secret 注入；配置文件只保存 provider 名称、模型策略和非敏感参数。
