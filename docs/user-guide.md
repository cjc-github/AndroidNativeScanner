# SOInsight V2 使用手册

> 本文档对应 2026-08-10 的仓库实现。V2 已搭建六大产品模块和 CLI 框架，并实现首个真实 `basic.file` Analyzer；其余能力保持 `partial` 或 `planned`。

## 1. 查看模块

```bash
soinsight modules list
soinsight modules show basic
soinsight modules list --format json
```

六个模块为 `basic`、`advanced`、`security`、`dynamic`、`ai`、`automation`。完整能力表见[模块体系](module-system.md)。

## 2. 运行单项能力

```bash
soinsight basic file libfoo.so
soinsight basic elf libfoo.so --format json
soinsight advanced strings libfoo.so
soinsight security hardening libfoo.so
soinsight dynamic trace libfoo.so
soinsight ai function-name libfoo.so
soinsight automation fuzz-target libfoo.so
```

当前命令会进入统一 Runtime。已注册的能力（如 `basic.file`、`basic.elf`、`security.hardening`）执行真实分析；未注册的能力（如 `basic.symbols`、`security.dangerous-api`）结构化返回 `ANALYSIS_PLAN_ERROR`。

## 3. 综合扫描

```bash
soinsight scan libfoo.so
soinsight scan libfoo.so --format json -o result.json
```

当前目标必须是存在的单个文件。TargetResolver 会记录真实路径、名称、大小、SHA-256 和扫描时间。

按产品模块选择：

```bash
soinsight scan libfoo.so --module basic,security --format json
```

精确选择能力实现：

```bash
soinsight scan libfoo.so --enable basic.file,basic.elf
```

`--module` 是用户侧领域选择，`--enable` 是 Analyzer ID 级别的精确选择。两者同时使用时会合并并去重，也可以与 YAML 配置共同使用。

## 4. 使用 Profile

```bash
soinsight scan libfoo.so --profile quick
soinsight scan libfoo.so --profile security
```

Profile 用于保存跨域能力组合。默认 CLI 已内置：

- `quick`：`basic.file`、`basic.elf`；
- `security`：`security.hardening`（含其依赖链）。

规划中的 Profile：

- `deep`：基础和高级静态分析；
- `ci`：稳定、可复现、适合风险门禁的组合。

## 5. 自动化能力

```bash
soinsight automation binary-diff old.so new.so
soinsight automation report result.json
soinsight automation workflow manifest.json
```

领域内的 `automation report/workflow` 代表产品自动化能力；顶层 `report` 当前只是技术性的 JSON 重格式化命令。后续二者应通过统一结果和工作流引擎衔接。

## 6. 输出

```bash
soinsight basic elf libfoo.so --format text
soinsight basic elf libfoo.so --format json
soinsight scan libfoo.so --format json --output result.json
```

当前支持 Text、JSON、Markdown、HTML。SARIF 尚未实现。

## 7. 环境诊断

```bash
soinsight doctor
soinsight doctor --format json
```

输出包含：SOInsight 版本、Python、产品模块数量、已注册 Analyzer 数量，以及 `readelf`、`nm`、`strings` 路径。

## 8. 模块与插件的区别

```bash
soinsight modules list   # 产品“准备提供什么”
soinsight plugins list   # 当前进程“实际加载了什么 Analyzer”
```

在当前阶段，模块数量为 6、能力数量为 42，而 Analyzer 数量为 1（`basic.file`）。这不是冲突：外部产品框架已建立，具体实现仍在迁移中。

## 9. 报告、缓存和 YAML 配置

```bash
soinsight report result.json --format json -o normalized.json
soinsight cache info
soinsight config create quick-security
soinsight config set quick-security analysis.modules.basic '[file, elf]'
soinsight config set quick-security analysis.modules.security '[hardening]'
soinsight config validate quick-security
soinsight config use quick-security
soinsight scan libfoo.so
```

也可以不激活配置，直接指定托管名称或外部路径：

```bash
soinsight scan libfoo.so --config quick-security
soinsight scan libfoo.so --config ./configs/quick-security.yaml
```

YAML 可以订制模块、模块内功能点、跨模块 capability、排除项、Runtime、输出和能力专属选项。显式 CLI 参数优先于 YAML；显式领域命令只运行该项能力，不会被 YAML 扩大。完整 Schema 和管理方式见 [YAML 配置指南](configuration.md)。

当前其他限制：

- `report` 不做完整 SOInsight Schema 校验；
- ArtifactStore 尚未接入 Runtime；
- `--jobs > 1` 已支持同 stage Analyzer 并发；资源预算和取消协调待做。

## 10. 常见诊断

| 诊断码 | 含义 |
|---|---|
| `NO_ANALYZERS_SELECTED` | 没有默认 Analyzer 或明确选择 |
| `INVALID_TARGET` | 目标不存在或不是当前支持的单文件 |
| `INVALID_CONFIGURATION` | jobs、timeout 等非法 |
| `INVALID_ANALYSIS_CONFIG` | YAML 不存在、格式错误或引用未知能力 |
| `MODULE_NOT_FOUND` | `--module` 包含未知模块 |
| `PROFILE_NOT_FOUND` | Profile 未注册 |
| `ANALYSIS_PLAN_ERROR` | Analyzer 缺失、依赖缺失或 DAG 规划失败 |
| `ANALYZER_EXCEPTION` | Analyzer 执行异常 |
| `DEPENDENCY_FAILED` | 必需上游未成功 |
| `RULE_EXCEPTION` | Rule 执行异常 |
