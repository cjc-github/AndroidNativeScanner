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

### 可选：提供人读文本摘要

实现 `format_text(result) -> str | None` 可以让 Web 控制台直接展示一段人类可读的文本，无需自己写渲染逻辑：

```python
def format_text(self, result):
    if result.status != AnalysisStatus.SUCCESS:
        return None
    data = result.data
    return f"=== 文件信息 ===\n路径: {data['name']}\n大小: {data['size']} 字节\n"
```

Runtime 会把返回值填入 `AnalysisResult.text` 并带入 JSON payload（`result.text` 字段，见 [CLI 输出 Schema](cli-output-schema.md)）。该钩子是可选的：不实现、返回 `None` 或抛异常都只会让 `text` 保持为空字符串，不影响分析本身。`text` 会随分析结果一起写入缓存，缓存命中时无需重新生成。

注意：命令行 `--format text` 的报告由 `renderers/text_renderer.py` 单独生成，**不读取** `text` 字段。

## 4. 声明跨域依赖

```python
class DangerousApiAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="security.dangerous-api",
        name="Dangerous API Detection",
        version="1.0.0",
        requires=("basic.symbols",),
    )

    def analyze(self, target, context):
        symbols = context.require("basic.symbols")
        ...
```

只能通过 Context 消费依赖结果，禁止直接实例化或调用其他 Analyzer。

`requires` 是硬依赖：Planner 会把它们拉进计划并在循环检查中覆盖。`optional_requires` 是软依赖（仅排序）：它**不会**把依赖拉进计划，只在该依赖因别的原因出现在计划里时要求先执行；消费方必须用 `context.optional()` 读取并在缺席时降级。真正必需的结果仍然只能放在 `requires`。软依赖会进入缓存键（见 `core/runtime/cache.py`），因此「有无该依赖」产生的不同事实不会互相污染。

内置 `basic.dwarf` 是跨基础设施依赖的例子：它 `requires=("basic.elf",)`，由 `infrastructure/dwarf` 解析调试信息，输出与 `basic.symbols` 在渲染层联合，而不是去调用 symbols 的实现。

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

能力实现应定义默认值、类型、范围和未知键策略；不要让 Renderer 或 CLI 解释某个 Analyzer 的业务参数。YAML 结构见 [配置指南](archive/configuration.md)。

## 8a. 复用二进制解析基础设施

需要 ELF 事实的能力应使用 `soinsight.infrastructure.elf`，不要自行拼 `struct` 或调用 `readelf`/`nm`：

```python
from soinsight.infrastructure.elf import decode_jni_symbol, demangle, parse_elf

elf = parse_elf(target.real_path)          # ElfFormatError 表示不是可解析 ELF
for symbol in elf.symbols_from(".dynsym"):
    if symbol.is_exported and symbol.is_function:
        decoded = demangle(symbol.name)    # 永不抛异常；失败时 kind == "undecoded"
        jni = decode_jni_symbol(symbol.name)  # 非 JNI 名返回 None
```

约定：

- 解析器对越界/截断的表按“未知”降级（返回空），只有魔法、类和入口大小非法才抛 `ElfFormatError`；
- `demangle()` 与 `decode_jni_symbol()` 永不抛异常，无法解释时原样返回，不做类型猜测；
- demangler 输出与 GNU `c++filt` 对齐（模板闭合前的空格规则、special-name 用自己的可读写法）；改 demangler 行为时同步更新 `tests/unit/test_demangler.py` 向量与 `tests/unit/test_demangler_oracle.py` 语料；
- 跨模块只通过 `AnalysisContext` 消费 `basic.symbols` 等上游结果。

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
