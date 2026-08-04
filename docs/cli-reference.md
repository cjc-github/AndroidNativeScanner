# SOInsight V2 CLI 命令参考

## 1. 主命令

```bash
soinsight --help
soinsight --version
```

当前版本：`2.0.0.dev0`。

## 2. 命令状态总览

| 命令 | 当前状态 | 说明 |
|---|---|---|
| `scan` | 框架可用 | 可解析单文件、规划 Analyzer、输出结果 |
| `file` | Runtime 已接入 | 缺少内置 `file` Analyzer |
| `elf` | Runtime 已接入 | 缺少内置 `elf` Analyzer |
| `symbols` | Runtime 已接入 | 缺少内置 `symbols` Analyzer |
| `strings` | Runtime 已接入 | 缺少内置 `strings` Analyzer |
| `security` | Runtime 已接入 | 缺少内置 `security` Analyzer |
| `report` | 基础可用 | 当前只读取和重新格式化 JSON |
| `plugins list` | 基础可用 | 展示已注册 Analyzer |
| `doctor` | 可用 | 检查 Python、版本和 binutils 工具 |
| `cache info` | 占位可用 | 只显示缓存路径 |
| `config show` | 占位可用 | 只显示默认值 |
| `dwarf` 等高级命令 | 占位 | 暂无具体实现，退出码 3 |

## 3. `scan`

```text
soinsight scan TARGET [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `TARGET` | 必填 | 当前必须是存在的单个文件 |
| `--enable IDS` | 默认 Analyzer | 逗号分隔的 Analyzer ID |
| `--profile ID` | 无 | 使用已注册 Profile |
| `--format` | `text` | `text` 或 `json` |
| `-o, --output` | stdout | 输出文件，`-` 表示 stdout |
| `-j, --jobs` | `1` | 配置项已保留，当前仍串行 |
| `--timeout` | `60` | 超时秒数，必须大于 0 |
| `-q, --quiet` | false | 静默配置入口 |
| `-v, --verbose` | false | 详细配置入口 |
| `--no-color` | false | 禁用颜色配置入口 |
| `--no-cache` | false | 禁用缓存配置入口 |
| `--cache-dir` | `.soinsight/cache` | 缓存目录配置入口 |
| `--fail-fast` | false | 快速失败配置入口 |

示例：

```bash
soinsight scan libfoo.so --enable file,elf --format json -o result.json
```

## 4. 基础单项分析命令

```text
soinsight {file|elf|symbols|strings|security} TARGET [OPTIONS]
```

参数与 `scan` 的 Runtime 参数相同，但不包含 `--enable` 和 `--profile`。命令会请求同名 Analyzer，并由 Planner 自动补全依赖。

## 5. `doctor`

```bash
soinsight doctor [--format text|json]
```

退出码为 0，即使某个外部工具缺失也只会在结果中显示 `not found`/`null`。后续可增加严格检查模式。

## 6. `plugins list`

```bash
soinsight plugins [list] [--format text|json]
```

JSON 元素字段：

```json
{
  "id": "elf",
  "kind": "collector",
  "name": "ELF Metadata",
  "requires": ["file"],
  "version": "1.0.0"
}
```

## 7. `report`

```bash
soinsight report INPUT [--format text|json] [-o OUTPUT]
```

输入不是合法 JSON 或文件不可读时返回退出码 2。

## 8. `cache info`

```bash
soinsight cache [info] [--cache-dir PATH]
```

当前只输出绝对缓存路径，不检查内容。

## 9. `config show`

```bash
soinsight config [show]
```

当前输出：

```text
Runtime defaults: jobs=1 timeout=60 cache=true
```

## 10. 高级占位命令

```bash
soinsight dwarf [TARGET]
soinsight disasm [TARGET]
soinsight cfg [TARGET]
soinsight callgraph [TARGET]
soinsight identify [TARGET]
soinsight diff [OLD] [NEW]
soinsight dynamic [TARGET]
soinsight fuzz [TARGET]
soinsight ai [TARGET]
```

这些命令当前输出“reserved”提示并返回退出码 3。

## 11. 当前退出码

| 退出码 | 当前含义 |
|---:|---|
| `0` | 命令或扫描框架成功 |
| `2` | 目标、配置或报告输入错误；`argparse` 参数错误也使用 2 |
| `3` | 分析计划错误、Analyzer 缺失或命令尚未实现 |
| `4` | Runtime 返回整体 `failed` |
| `5` | Runtime 返回 `partial` |

设计中预留的风险阈值退出码 `1` 尚未实现。
