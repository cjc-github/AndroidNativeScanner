# SOInsight V2 扩展开发指南

## 1. 先确定产品能力

新增实现前，先确认它属于六大产品模块中的哪项能力：

```text
basic / advanced / security / dynamic / ai / automation
```

如果是已有能力，在对应目录使用稳定 ID；如果确实需要新增能力，先更新 `src/soinsight/modules/<domain>/__init__.py` 和 `docs/module-system.md`。不要把 Analyzer、Rule、Renderer 或某个第三方工具名称新增为一级产品模块。

## 2. Analyzer ID

Analyzer ID 必须 namespaced：

```text
basic.file
basic.elf
advanced.strings
security.hardening
```

禁止新增无命名空间的 `file`、`elf`、`security` 等 ID。开发期扁平 CLI 别名只用于兼容，不是 Analyzer ID 规范。

## 3. 最小 Analyzer

```python
from soinsight.core.analyzer import Analyzer, AnalyzerMetadata
from soinsight.core.models import AnalysisResult, AnalysisStatus


class FileAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="basic.file",
        name="File Analysis",
        version="1.0.0",
        description="Collect file metadata and fingerprints",
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

- ID 全局唯一并与能力目录一致；
- 返回 ID 与注册 ID 一致；
- 数据可 JSON 序列化；
- 不直接打印或决定退出码；
- 可降级问题写入 Diagnostic；
- 未知异常交给 Runtime 隔离。

## 4. 声明跨域依赖

```python
class DangerousApiAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="security.dangerous-api",
        name="Dangerous API Detection",
        version="1.0.0",
        requires=(
            "basic.symbols",
            "basic.disasm",
            "basic.callgraph",
        ),
    )

    def analyze(self, target, context):
        symbols = context.require("basic.symbols")
        disasm = context.require("basic.disasm")
        callgraph = context.require("basic.callgraph")
        ...
```

只能通过 Context 消费依赖结果，禁止直接实例化或调用其他 Analyzer。

`optional_requires` 已存在于元数据，但当前 Planner 尚未自动调度可选依赖；真正必需的结果必须放在 `requires`。

## 5. 注册内置 Analyzer

在 `src/soinsight/analyzers/builtin.py` 集中注册：

```python
from .file import FileAnalyzer
from .elf import ElfAnalyzer


def register_builtin_analyzers(registry):
    registry.register_many([FileAnalyzer(), ElfAnalyzer()])
```

验证：

```bash
PYTHONPATH=src python3 -m soinsight plugins list
PYTHONPATH=src python3 -m soinsight basic file README.md --format json
```

## 6. 调用外部工具

使用 `ToolRunner`，不要拼接 shell 字符串：

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

必须处理返回码、超时、截断、stderr 和工具缺失。动态分析还必须增加显式授权、沙箱、资源限制和目标生命周期控制。

## 7. Rule

Rule 消费 Analyzer 的事实并生成 Finding：

```python
from soinsight.core.models import Confidence, Finding, Severity
from soinsight.core.rules import Rule, RuleMetadata


class MissingPieRule(Rule):
    metadata = RuleMetadata(
        id="security.hardening.missing-pie",
        name="Missing PIE",
        version="1.0.0",
        requires=("security.hardening",),
    )

    def evaluate(self, context):
        hardening = context.require("security.hardening")
        if hardening.data.get("pie") is not False:
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

事实采集放 Analyzer，可配置判断放 Rule，最终排版放 Renderer。

## 8. Profile

```python
from soinsight.core.profiles import ProfileRegistry, ScanProfile

profiles.register(
    ScanProfile(
        id="quick",
        name="Quick Scan",
        analyzer_ids=("basic.file", "basic.elf", "basic.symbols"),
        description="Fast cross-capability metadata scan",
    )
)
```

Profile 可以跨模块组合，但应使用稳定 capability/Analyzer ID。

Analyzer 的可订制参数从 `context.config.extra["capability_options"]` 读取，并以自身 namespaced ID 取值：

```python
options = context.config.extra.get("capability_options", {}).get(
    self.metadata.id, {}
)
min_length = int(options.get("min_length", 4))
```

能力实现应定义默认值、类型、范围和未知键策略；不要让 Renderer 或 CLI 解释某个 Analyzer 的业务参数。YAML 结构见 [配置指南](configuration.md)。

## 9. Renderer

```python
from soinsight.renderers.base import Renderer


class MarkdownRenderer(Renderer):
    format = "markdown"

    def render(self, response):
        return "# SOInsight Result\n"
```

注册 Renderer 后还需扩展 CLI `--format` choices 和测试。

## 10. AI 与自动化实现约束

- AI Analyzer 消费基础/高级/安全结果，输出建议、证据引用、模型和提示版本；
- AI 结论不得覆盖确定性事实；
- 敏感二进制、符号和字符串默认不发送到远程 Provider；
- 自动化模块负责编排已有能力，不复制底层分析；
- Binary Diff 等多目标能力需要先扩展 Request/TargetSet 模型，不应塞入单目标 Analyzer 接口。

## 11. 测试要求

每个 Analyzer 至少覆盖：

1. 正常输入；
2. 非 ELF 或损坏输入；
3. 外部工具缺失/失败/超时；
4. 依赖缺失和上游失败；
5. JSON 可序列化；
6. namespaced ID 与模块目录一致；
7. CLI Text/JSON；
8. V1 对照或 Golden 样本（适用时）。

提交前运行：

```bash
PYTHONPATH=src python3 -m pytest -q
python3 -m compileall -q src/soinsight
./scripts/build_cli.sh
git diff --check
```

## 12. 通过 Entry Point 分发插件

外部包可以通过 Python entry point 组 `soinsight.analyzers` 暴露 Analyzer。每个 entry point 必须加载一个可调用对象，返回一个 Analyzer 实例或可迭代的 Analyzer 实例集合。

在外部包的 `setup.cfg` 中声明：

```ini
[options.entry_points]
soinsight.analyzers =
    my-plugin = mypackage.plugin:create_analyzers
```

对应的工厂函数：

```python
from mypackage.plugin import MyAnalyzer


def create_analyzers():
    return MyAnalyzer()
```

安装该包后，`soinsight plugins list` 会显示自动加载的插件 Analyzer。内置 Analyzer 仍通过 `src/soinsight/analyzers/builtin.py` 注册；entry point 加载发生在 CLI 构造默认注册表时。
