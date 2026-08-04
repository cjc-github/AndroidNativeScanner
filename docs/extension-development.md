# SOInsight V2 扩展开发指南

## 1. 新增 Analyzer

Analyzer 负责提取或转换事实，返回结构化 `AnalysisResult`。

### 1.1 最小实现

```python
from soinsight.core.analyzer import Analyzer, AnalyzerMetadata
from soinsight.core.models import AnalysisResult, AnalysisStatus


class FileAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="file",
        name="File Metadata",
        version="1.0.0",
        description="Collect basic file metadata",
    )

    def analyze(self, target, context):
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "name": target.name,
                "size": target.size,
                "sha256": target.sha256,
            },
        )
```

约束：

- `metadata.id` 必须非空且全局唯一；
- 返回的 `analyzer_id` 必须与注册 ID 一致；
- 数据必须可序列化为 JSON；
- 不直接打印终端输出；
- 不捕获后又静默丢弃错误；
- 能降级时返回诊断，不能继续时允许抛出异常，由 Runtime 隔离。

### 1.2 声明依赖

```python
class ElfAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="elf",
        name="ELF Metadata",
        version="1.0.0",
        requires=("file",),
    )

    def analyze(self, target, context):
        file_result = context.require("file")
        ...
```

可选结果：

```python
symbols_result = context.optional("symbols")
```

`optional_requires` 字段已经存在，但当前 Planner 不会自动加入可选依赖。如果 Analyzer 需要某结果才能工作，应放入 `requires`。

### 1.3 注册内置 Analyzer

在 `src/soinsight/analyzers/builtin.py` 中注册：

```python
from .file import FileAnalyzer
from .elf import ElfAnalyzer


def register_builtin_analyzers(registry):
    registry.register_many([
        FileAnalyzer(),
        ElfAnalyzer(),
    ])
```

注册后验证：

```bash
PYTHONPATH=src python3 -m soinsight plugins list
PYTHONPATH=src python3 -m soinsight file README.md --format json
```

## 2. 调用外部工具

Analyzer 应通过 `ToolRunner` 调用外部程序：

```python
from soinsight.infrastructure.tools import ToolRequest, ToolRunner

result = ToolRunner().run(
    ToolRequest(
        executable="readelf",
        arguments=("-h", str(target.real_path)),
        timeout_seconds=context.config.timeout_seconds,
    )
)
```

必须处理：

- `result.return_code`；
- `result.timed_out`；
- `result.truncated`；
- stderr；
- 工具不存在。当前 `ToolRunner` 对不存在的 executable 会抛出异常，由 Runtime 转换为 `ANALYZER_EXCEPTION`；具体 Analyzer 后续应提供更明确诊断。

禁止使用拼接后的 shell 字符串执行不可信路径。

## 3. 新增 Rule

Rule 消费 Analyzer 结果并生成 Finding：

```python
from soinsight.core.models import Confidence, Finding, Severity
from soinsight.core.rules import Rule, RuleMetadata


class MissingPieRule(Rule):
    metadata = RuleMetadata(
        id="elf.security.missing-pie",
        name="Missing PIE",
        version="1.0.0",
        requires=("elf",),
    )

    def evaluate(self, context):
        elf = context.require("elf")
        if elf.data.get("pie") is not False:
            return []
        return [
            Finding(
                rule_id=self.metadata.id,
                rule_version=self.metadata.version,
                title="PIE is not enabled",
                category="hardening",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                message="The ELF does not appear to use PIE.",
                remediation="Enable position-independent executable settings.",
            )
        ]
```

当前 CLI 默认 Runtime 使用空 `RuleRegistry`。在内置规则接入前，需要构造 `RuleEngine(registry)` 并注入 `AnalysisRuntime`，或者后续增加统一内置 Rule 注册入口。

## 4. 新增 Profile

```python
from soinsight.core.profiles import ProfileRegistry, ScanProfile

profiles = ProfileRegistry()
profiles.register(
    ScanProfile(
        id="quick",
        name="Quick Scan",
        analyzer_ids=("file", "elf"),
        description="Fast metadata scan",
    )
)
```

CLI `main()` 支持注入 ProfileRegistry，默认实例当前为空。后续内置 Profile 应集中注册，避免散落在命令处理代码中。

## 5. 新增 Renderer

```python
from soinsight.renderers.base import Renderer


class MarkdownRenderer(Renderer):
    format = "markdown"

    def render(self, response):
        return "# SOInsight Result\n"
```

注册：

```python
renderer_registry.register(MarkdownRenderer())
```

注意：还需要把 CLI `--format` choices 扩展为新格式，否则命令行不会接受该值。

## 6. Analyzer 设计建议

推荐 ID：

```text
file
elf
elf.sections
elf.dynamic
symbols
strings
security.hardening
```

推荐职责边界：

- Collector：读取文件或工具输出，产生事实；
- Transformer：基于已有结果生成中间表示；
- Detector：检测模式或产生候选问题；
- Rule：形成正式 Finding 和风险级别；
- Renderer：只负责展示。

不要在单个 Analyzer 中同时完成 ELF 解析、风险评分、文本报告和文件写入。

## 7. 测试要求

每个 Analyzer 至少覆盖：

1. 正常输入；
2. 工具缺失或返回非 0；
3. 超时；
4. 损坏/非 ELF 输入；
5. 返回数据可以 JSON 序列化；
6. 依赖成功和失败；
7. 不把异常 traceback 直接泄漏到 CLI。

运行测试：

```bash
PYTHONPATH=src python3 -m pytest -q
```

建议结构：

```text
tests/unit/test_<analyzer>.py
tests/integration/test_<command>_cli.py
tests/fixtures/
```

## 8. 完成定义

一个 Analyzer 只有满足以下条件才算接入完成：

- 已实现并注册；
- `plugins list` 可见；
- 单项命令可运行；
- `scan --enable` 可组合；
- 依赖由 Planner 自动补全；
- Text/JSON 均可输出；
- 失败产生结构化 Diagnostic；
- 有单元测试和至少一个 CLI 集成测试；
- 使用文档和状态文档同步更新。
