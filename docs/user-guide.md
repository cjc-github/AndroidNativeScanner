# SOInsight V2 使用手册

> 本文档描述 2026-08-04 仓库中的实际实现。规划中的命令会明确标注为“占位”。

## 1. 基本语法

```text
soinsight [--version] COMMAND [COMMAND_OPTIONS]
```

查看主帮助：

```bash
soinsight --help
```

查看子命令帮助：

```bash
soinsight scan --help
soinsight doctor --help
```

## 2. 扫描单个文件

```bash
soinsight scan <target>
```

当前 TargetResolver 只接受存在的单个文件，不支持目录：

```bash
soinsight scan libfoo.so
soinsight scan libfoo.so --format json
soinsight scan libfoo.so --format json -o result.json
```

未注册 Analyzer 时，扫描仍会建立目标信息，包括：

- 输入路径和真实路径；
- 文件名；
- 文件大小；
- SHA-256；
- 扫描开始时间；
- Schema 和工具版本；
- 诊断信息。

## 3. 选择 Analyzer

显式选择：

```bash
soinsight scan libfoo.so --enable file,elf,symbols
```

不传 `--enable` 时，使用 Registry 中 `default_enabled=True` 的 Analyzer。

通过 Profile 选择：

```bash
soinsight scan libfoo.so --profile quick
```

当前默认 CLI 没有注册内置 Profile，因此只有应用注入或后续内置 Profile 注册后才能使用。未知 Profile 会返回规划错误。

Analyzer 依赖会由 Planner 自动补全。例如 `elf` 声明 `requires=("file",)` 后，只请求 `elf` 也会先执行 `file`。

## 4. 单项命令

以下命令已经接入统一 Runtime，但目前没有对应内置 Analyzer：

```bash
soinsight file libfoo.so
soinsight elf libfoo.so
soinsight symbols libfoo.so
soinsight strings libfoo.so
soinsight security libfoo.so
```

在 Analyzer 尚未注册时，它们会返回 `ANALYSIS_PLAN_ERROR` 和退出码 `3`。

## 5. 输出格式

### Text

```bash
soinsight scan libfoo.so --format text
```

Text 输出包含目标、SHA-256、状态、已解析 Analyzer、Finding 数量、耗时和诊断信息。

### JSON

```bash
soinsight scan libfoo.so --format json
```

顶层结构：

```json
{
  "diagnostics": [],
  "exit_code": 0,
  "result": {
    "schema_version": "soinsight.scan/v1",
    "status": "success",
    "target": {},
    "results": {},
    "findings": [],
    "diagnostics": []
  }
}
```

JSON 是自动化集成的优先格式。消费者应检查 `schema_version`，不要依赖未声明的字段顺序。

### 写入文件

```bash
soinsight scan libfoo.so --format json --output result.json
soinsight scan libfoo.so --format json --output -
```

父目录不存在时会自动创建。

## 6. Runtime 参数

```bash
soinsight scan libfoo.so \
  --jobs 1 \
  --timeout 60 \
  --no-color \
  --no-cache \
  --cache-dir .soinsight/cache \
  --fail-fast
```

当前实现边界：

- `--jobs` 已进入配置模型，但 Scheduler 仍是串行执行；
- `--timeout` 已进入配置模型，Analyzer 应将其传递给 `ToolRunner`；
- `--no-cache` 和 `--cache-dir` 已进入配置模型，但 Runtime 尚未接入缓存；
- `--fail-fast` 已进入配置模型，但串行 Scheduler 尚未使用该选项停止后续独立任务；
- `--quiet`、`--verbose`、`--no-color` 已保留，完整日志和颜色策略尚未实现。

这些参数已经形成稳定入口，但不能误认为相应高级行为已经全部完成。

## 7. 环境检查

```bash
soinsight doctor
soinsight doctor --format json
```

检查内容：

- SOInsight 版本；
- Python 版本和解释器路径；
- 已注册 Analyzer 数量；
- `readelf`、`nm`、`strings` 的路径。

`doctor` 当前只报告状态，不会自动安装依赖。

## 8. Analyzer 列表

```bash
soinsight plugins list
soinsight plugins list --format json
```

当前这里展示的是 Analyzer Registry 内容。外部插件自动发现尚未实现。

## 9. 报告读取

```bash
soinsight report result.json
soinsight report result.json --format text
soinsight report result.json --format json -o normalized.json
```

当前 `report` 功能只负责读取并验证输入是否为合法 JSON：

- `--format json`：重新格式化 JSON；
- `--format text`：输出输入是合法 JSON 的提示；
- 尚未执行完整 SOInsight Schema 校验；
- 尚未生成 Markdown 或 HTML 报告。

## 10. Cache 和 Config

```bash
soinsight cache info
soinsight cache info --cache-dir /tmp/soinsight-cache
soinsight config show
```

当前：

- `cache info` 只显示缓存目录；
- `config show` 只显示 Runtime 默认值；
- 配置文件和环境变量合并尚未实现；
- 缓存查看、清理、统计尚未实现。

## 11. 占位命令

以下命令只保留 CLI 入口，执行时返回退出码 `3`：

```text
dwarf, disasm, cfg, callgraph, identify,
diff, dynamic, fuzz, ai
```

它们用于稳定未来命令空间，不代表对应功能已经可用。

## 12. 状态和诊断

常见诊断码：

| 诊断码 | 含义 |
|---|---|
| `NO_ANALYZERS_SELECTED` | 没有注册或选中 Analyzer |
| `INVALID_TARGET` | 输入不存在或当前不是单个文件 |
| `INVALID_CONFIGURATION` | jobs、timeout 等配置非法 |
| `ANALYSIS_PLAN_ERROR` | Analyzer/Profile 缺失或依赖规划失败 |
| `ANALYZER_EXCEPTION` | Analyzer 执行抛出异常 |
| `DEPENDENCY_FAILED` | 必需的上游 Analyzer 未成功 |
| `RULE_DEPENDENCY_MISSING` | Rule 所需结果不可用 |
| `RULE_EXCEPTION` | Rule 执行异常 |

详细命令和退出码参见 [CLI 命令参考](cli-reference.md)。
