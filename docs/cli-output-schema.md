# SOInsight CLI 输出 Schema

本文档说明 SOInsight CLI 当前稳定机器输出。所有 JSON 输出必须满足以下约束：

- 不包含 ANSI 颜色；
- 顶层字段使用 snake_case；
- 退出码仍以进程退出码为准，JSON 中的 `exit_code` 仅作为记录；
- 人类可读 `text` 输出的表格、颜色、宽度适配不影响 JSON 字段。

## 1. 通用响应 Envelope

分析类命令的 JSON 输出使用统一 Envelope：

```json
{
  "result": {},
  "diagnostics": [],
  "exit_code": 0
}
```

字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `result` | object 或 null | 成功或部分成功时为扫描结果；规划/输入错误时可为 null |
| `diagnostics` | array | 命令级诊断列表 |
| `exit_code` | integer | 对应 CLI 退出码 |

## 2. ScanResult

`result` 为扫描结果时包含：

| 字段 | 类型 | 说明 |
|---|---|---|
| `target` | object | 目标文件摘要 |
| `status` | string | `success`、`failed`、`partial` 等运行状态 |
| `results` | object | Analyzer ID 到 AnalysisResult 的映射 |
| `findings` | array | 聚合后的 Finding 列表 |
| `diagnostics` | array | 扫描级诊断 |
| `requested_analyzers` | array[string] | 用户或配置请求的 Analyzer ID |
| `resolved_analyzers` | array[string] | DAG 解析后的 Analyzer ID |
| `profile` | string 或 null | 使用的 Profile |
| `started_at` | string | ISO-8601 时间 |
| `duration_ms` | integer | 总耗时毫秒 |
| `schema_version` | string | 当前为 `soinsight.scan/v1` |
| `tool_version` | string | SOInsight 版本 |

## 3. AnalysisResult

`results.<analyzer_id>` 包含：

| 字段 | 类型 | 说明 |
|---|---|---|
| `analyzer_id` | string | Analyzer ID，例如 `basic.file` |
| `analyzer_version` | string | Analyzer 版本 |
| `status` | string | Analyzer 执行状态 |
| `data` | object | Analyzer 输出事实 |
| `findings` | array | Analyzer 产生的 Finding |
| `diagnostics` | array | Analyzer 诊断 |
| `duration_ms` | integer | Analyzer 耗时毫秒 |
| `cache_hit` | boolean | 是否命中缓存 |
| `schema_version` | string | 当前为 `soinsight.result/v1` |

## 4. modules JSON

```bash
soinsight modules list --format json
soinsight modules show basic --format json
```

返回模块数组：

```json
[
  {
    "id": "basic",
    "name": "基础分析",
    "description": "...",
    "capabilities": [
      {
        "id": "basic.file",
        "command": "file",
        "name": "文件分析",
        "description": "...",
        "target_arguments": ["target"]
      }
    ]
  }
]
```

注意：实现状态是 text 输出的辅助信息；当前 JSON 保持产品目录 schema，不额外注入状态字段。

## 5. plugins JSON

```bash
soinsight plugins list --format json
```

返回 Analyzer 元数据数组：

```json
[
  {
    "id": "basic.file",
    "name": "File Analyzer",
    "version": "1.0.0",
    "kind": "collector",
    "requires": []
  }
]
```

## 6. doctor JSON

```bash
soinsight doctor --format json
```

返回：

```json
{
  "soinsight_version": "2.0.0.dev0",
  "python_version": "3.10.12",
  "python_executable": "/usr/bin/python3",
  "product_modules": 6,
  "registered_analyzers": 1,
  "legacy_tools": {
    "readelf": "/usr/bin/readelf",
    "nm": "/usr/bin/nm",
    "strings": "/usr/bin/strings"
  }
}
```

## 7. P2 text-only behavior

P2 终端体验能力仅影响 `text` 输出：

- TTY 下默认启用状态颜色；
- `--no-color` 禁用颜色；
- JSON 输出永不带颜色；
- `--quiet` 在成功分析时不输出正文，失败时仍输出错误摘要；
- 窄终端下 `modules list` 使用紧凑布局。
