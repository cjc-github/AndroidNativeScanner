# SOInsight V2 架构说明

## 1. 架构原则

V2 使用“**领域化产品结构 + 模块化单体技术内核**”。需要区分：

- **产品模块**：基础、高级、安全、动态、AI、自动化；
- **技术机制**：CLI、Analyzer、Rule、Planner、Scheduler、Renderer、Store 等。

产品模块回答“用户获得什么能力”，技术机制回答“能力如何实现和复用”。当前不引入 Web 服务、微服务或强制数据库。

## 2. 总体分层

```text
┌──────────────────────────────────────────────────────────────┐
│ Product Capability Layer                                     │
│ Basic │ Advanced │ Security │ Dynamic │ AI │ Automation      │
│ 领域命令、能力目录、稳定 capability ID、用户心智模型          │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│ CLI / Application Orchestration                              │
│ 参数解析 │ YAML Config │ TargetResolver │ Request │ Profile │ 输出控制 │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│ Shared Analysis Core                                        │
│ Analyzer SDK/Registry │ Rule Engine │ DAG Planner │ Scheduler │
│ Context │ Result/Finding/Diagnostic │ Aggregator              │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│ Infrastructure / Adapters                                   │
│ ToolRunner │ ArtifactStore │ PluginLoader │ Config │ Provider  │
│ ELF Parser │ C++ Demangler │ JNI Decoder                     │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│ Renderers / Integrations                                    │
│ Text │ JSON │ future Markdown/HTML/SARIF │ CI                 │
└──────────────────────────────────────────────────────────────┘
```

## 3. 代码结构与职责

### Product Capability Layer

位置：`src/soinsight/modules/`

职责：

- 注册六个一级产品模块；
- 定义能力名称、命令、稳定 ID 和输入形态；
- 为 CLI、文档、Profile 和能力发现提供单一目录；
- 校验能力 ID 必须使用 `<module>.<capability>` 命名空间。

该层只描述“有哪些能力”，不直接实现 ELF 解析。

### CLI Layer

位置：`src/soinsight/cli/`

职责：构建领域命令树、解析参数、选择模块/能力、映射输出和退出码。CLI 不包含分析逻辑。

### Application Layer

位置：`src/soinsight/application/`

职责：解析目标、构造请求、调用 Runtime，并将领域异常转换为结构化响应。

### Core Layer

位置：`src/soinsight/core/`

职责：统一模型、Analyzer/Rule/Profile SDK、DAG Planner、Scheduler、Context 和聚合。

### Analyzer Implementations

位置：`src/soinsight/analyzers/`

具体能力实现应注册与能力目录一致的 namespaced ID，例如 `basic.elf`。Analyzer 是内部最小执行单元，不是一级产品模块。

### Infrastructure Layer

位置：`src/soinsight/infrastructure/`

隔离 YAML 配置仓库、subprocess、文件缓存、外部插件和序列化等易变化细节。`infrastructure/config` 当前提供类型化 Schema、原子写入、托管目录和活动配置指针。

`infrastructure/elf` 是二进制解析边界：

- `parser.py`：Header/ProgramHeader/SectionHeader/Symbol 表解码，ELF32 与 ELF64，全部读取做边界检查；声明了但越界的表按“未知”降级，不视为错误；
- `demangle.py`：Itanium C++ ABI 符号 demangler，覆盖真实 ELF 导出常见的子集（嵌套名、模板与替换、操作符、构造析构、local name、vtable/typeinfo/guard/thunk、TM clone），无法解释的名字原样返回而不猜测。替换编号遵循参考 mangler：名称类候选去重（`find_substitution` 先行），类型类候选不去重（解析出的模板参数会再次登记）；
- `jni.py`：JNI native 方法名解码，转义感知的组件切分。

`infrastructure/dwarf` 解析调试信息：

- `parser.py`：`.debug_info`/`.debug_abbrev`/`.debug_str`/`.debug_line_str` 与 `.debug_line` 行号表头，支持 DWARF 2-5（含 DWARF64 与 DWARF5 的 `unit_type` 布局差异），提取 `DW_TAG_subprogram` 的形式参数、参数类型、返回类型与 `DW_AT_decl_file`/`DW_AT_decl_line`，并按父 DIE 链还原类/命名空间限定名；
- 未知 form、越界引用、缺失字符串表都降级为 `None` 而不是猜测；`.debug_info` 畸形时记 `DWARF_UNREADABLE` 警告，不影响其余分析。

该层不依赖 `readelf`/`nm`/`objdump` 等外部工具，也不执行被分析文件。验证方式见[项目状态](project-status.md)的“真实共享库验证”。

运行时控制位于 `core/runtime`：

- `scheduler.py`：每个 Analyzer 在守护线程中执行并受看门狗约束，超时记 `ANALYZER_TIMEOUT`；Python 无法终止线程，因此用 daemon 线程以保证 Ctrl+C 仍能退出，被放弃线程对共享 context 的写入是尽力而为；
- `progress.py`：`ProgressObserver` 在 run/stage/analyzer 边界发事件，供 CLI 进度行或未来前端日志流使用；观察者抛异常不会影响分析结果；
- `runtime.py`：接受外部 `CancellationToken`，使前端（或 CLI 的 SIGINT）能在 Analyzer 之间协作式取消。

### Renderer Layer

位置：`src/soinsight/renderers/`

把 `ApplicationResponse` 转换为 Text/JSON 等格式；不得重新执行分析。

## 4. 调用链

配置驱动的综合扫描：

```text
scan --config NAME / active-config
  → YamlConfigStore.load + Schema 校验
  → 模块功能点展开 + Profile/CLI 合并 + exclude
  → CLI > YAML > Runtime 默认值
  → capability_options 注入 RuntimeConfig.extra
  → AnalysisRequest → Runtime → Renderer
```

显式领域命令只复用 YAML 的 Runtime、输出和能力参数，能力选择仍固定为该命令。`Profile` 是稳定能力包，YAML Config 是用户分析策略，Workflow 是未来的多阶段/多目标编排。

单能力命令：

```text
soinsight security dangerous-api libfoo.so
  → ModuleCatalog 解析 security.dangerous-api
  → CLI 构造 AnalysisRequest
  → TargetResolver 校验目标并计算 SHA-256
  → DependencyPlanner 补全 basic.file → basic.elf → basic.symbols
  → Scheduler 按 DAG 执行 Analyzer（看门狗 + 进度事件 + 取消令牌）
  → SecurityDangerousApiAnalyzer 从 AnalysisContext 读取 basic.symbols 事实并生成 Finding
  → ResultAggregator 生成 ScanResult
  → Renderer 输出 text/json
```

已实现的符号链路：

```text
soinsight basic symbols libfoo.so
  → ModuleCatalog 解析 basic.symbols
  → DependencyPlanner 补全 basic.file → basic.elf
  → infrastructure/elf 解析 .dynsym/.symtab
  → demangle / decode_jni_symbol 恢复签名
  → Renderer 输出 text/json/markdown/html
```

已实现的调试信息链路：

```text
soinsight basic dwarf libfoo.so
  → DependencyPlanner 补全 basic.file → basic.elf
  → infrastructure/dwarf 解析 .debug_info/.debug_line
  → 参数名/参数类型/返回类型/声明位置 + 父 DIE 链限定名
  → 与 basic.symbols 在渲染层按 mangled name 联合
```

组合扫描：

```text
soinsight scan libfoo.so --module-available basic,security
  → ModuleCatalog 展开两个领域已注册的能力 ID
  → Planner 去重并补全跨域依赖
  → Runtime 执行统一计划
```

## 5. 依赖模型

```python
AnalyzerMetadata(
    id="security.dangerous-api",
    name="Dangerous API Detection",
    version="1.0.0",
    requires=("basic.symbols",),
)
```

`basic.dwarf` 依赖 `basic.elf`；`security.dangerous-api` 依赖 `basic.symbols`。`basic.disasm`/`basic.callgraph` 尚未实现，不进入当前依赖链。

Planner 负责：

- 递归补全硬依赖；
- 检测缺失 Analyzer；
- 检测循环依赖；
- 按拓扑 stage 排序；
- 在上游失败时跳过下游。

跨域依赖不是模块耦合。下游只能从 `AnalysisContext` 读取标准结果，不能直接调用上游实现。

## 6. 统一结果

所有能力共享：

- `AnalysisTarget`：目标身份、路径、大小、SHA-256；
- `AnalysisResult`：Analyzer 状态、数据、诊断和版本；
- `Finding`：规则、严重度、置信度、证据和修复建议；
- `ScanResult`：跨能力聚合结果；
- `Diagnostic`：配置、规划、执行和降级信息。

AI 和自动化能力应消费这些结果，避免重复解析原始文件。

## 7. 状态与失败隔离

状态模型：

```text
pending, running, success, partial, skipped,
timeout, failed, cancelled, cached
```

Scheduler 产生 `success`、`failed`、`skipped`、`timeout`、`cancelled`、`cached`。单个 Analyzer 异常被转换为诊断；无关 DAG 分支可以继续运行。看门狗超时后线程被放弃（Python 无法终止线程），其结果按尽力而为处理。

## 8. 扩展点

| 扩展点 | 用途 | 当前状态 |
|---|---|---|
| Module Catalog | 产品模块与能力发现 | 已实现六大模块 |
| Analyzer | 提取/转换事实 | SDK 可用；9 个内置 Analyzer（file/elf/symbols/dwarf/strings/hardening/dangerous-api/vulnerability/risk） |
| Rule | 从事实形成 Finding | SDK 和 Runtime 可用 |
| Profile | 组合能力 | Registry 可用，内置 `quick`/`security` |
| Renderer | 输出格式 | Text/JSON/Markdown/HTML/SARIF 已实现 |
| Scheduler | 任务执行 | DAG stage 并发、看门狗、取消与进度可用 |
| Artifact Store | 中间结果缓存 | 文件实现存在，未接 Runtime |
| Plugin Loader | 外部扩展发现 | entry point 组 `soinsight.analyzers` 自动发现 |
| Provider Adapter | AI/动态/反编译等外部能力 | 待设计 |

## 9. 包依赖约束

```text
cli → modules + application + renderers
application → core
analyzers → core + selected infrastructure
infrastructure → core contracts
core 不依赖 cli/modules/具体 analyzer
```

禁止：

- 用 Analyzer/Rule 等技术类型替代六大产品模块；
- Analyzer 解析 CLI 参数或直接打印；
- Analyzer 直接调用另一个 Analyzer；
- Rule 重新执行已有事实采集；
- AI 能力绕过统一结果自行重复扫描；
- 动态分析默认执行不可信目标。

## 10. 当前差距

1. 为能力目录接入更多真实 Analyzer 和跨域依赖（当前 9/42 项能力已接入）；
2. 支持双目标、多样本、结果集等复杂输入模型；
3. 内置 deep/ci Profile（`quick`/`security` 已实现）；
4. Artifact Store 接入 Runtime；
5. Scheduler 资源预算（stage 并发、看门狗与取消已实现）；
6. 外部插件 API 兼容策略；
7. JSON Schema、Golden 回归；
8. 动态分析沙箱和 AI Provider 治理；
9. V1 Compatibility Adapter。
