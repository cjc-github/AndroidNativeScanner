# SOInsight V2.0 CLI 工具箱软件设计说明书（SDS）

> SOInsight V2 的主设计文档。以基础分析、高级分析、安全分析、动态分析、AI 分析和自动化六大产品能力域为核心，定义 CLI、编排、扩展、数据、安全和演进方式。

## 1. 文档信息

| 项目 | 内容 |
|---|---|
| 文档版本 | 2.0（SDS 修订版 2.2） |
| 文档状态 | V2 主设计 / Master Design（外部框架已实现，具体能力持续建设） |
| 更新日期 | 2026-08-04 |
| 产品基线 | 六大能力域、统一 IR、插件化分析与自动化目标 |
| 实现基线 | Android Native Scanner V1 + SOInsight V2 Framework `2.0.0.dev0` |
| 目标形态 | 本地优先、领域化、可组合、可扩展的 CLI 工具箱 |

本文中的“模块”默认指六个产品能力域。本文是 V2 唯一主设计基线；各能力的详细 SDS 应引用本文，而不是重新定义一级模块。Analyzer、Rule、Planner、Scheduler、Renderer、Artifact Store 等称为“技术组件”或“扩展点”，不作为产品一级模块。

## 2. 版本演进

### 2.1 V1

V1 已有 ELF Header、符号、字符串、URL/敏感信息/Base64/JNI 检测、单文件和目录扫描、文本风险汇总。其价值是已有实现和样本行为，限制是结果模型、依赖编排、可扩展性和自动化接口不足。

### 2.2 V2 产品模型

V2 保留最初确定的统一 IR、插件化架构及六大能力域共 40 项核心能力。六大能力域是产品边界，不能被 Analyzer、Rule、Renderer 等技术分类替代。

### 2.3 SDS 修订目标

本次修订将能力规划升级为可执行的软件设计：

- 保留六大领域及 40 项能力；
- 补充报告自动化、工作流/批处理/CI Gate 两项编排能力；
- 为每项能力定义 namespaced ID 和领域命令；
- 将 Analyzer/Rule 等下沉为跨领域共享实现机制；
- 定义 DAG、统一结果、安全边界、迁移和验收策略。

## 3. 项目定位

SOInsight V2 是面向 Linux/Android ELF 动态库的模块化 CLI 工具箱。它以六大产品能力域对外提供能力：

```text
SOInsight V2
├── 基础分析 Basic
├── 高级分析 Advanced
├── 安全分析 Security
├── 动态分析 Dynamic
├── AI 分析 AI
└── 自动化 Automation
```

CLI 是首要交付形态；Web、REST API 或企业平台可在稳定 CLI/Application API 之上建设，不进入 V2 核心首期范围。

## 4. 设计目标

### 4.1 产品目标

- **领域清晰**：用户按六大能力域发现和使用功能；
- **工具箱化**：每项能力可独立调用；
- **可组合**：能力可通过 `scan`、Profile 或 Workflow 组合；
- **自动化友好**：稳定 JSON、退出码、无颜色输出、CI Gate；
- **渐进迁移**：V1 在 V2 具备真实替代能力前继续工作。

### 4.2 架构目标

- 能力目录与实现解耦；
- 跨域依赖由 DAG 声明，不直接调用；
- 事实、Finding、解释和报告分离；
- 统一 Target、Result、Finding、Diagnostic 和版本字段；
- 外部工具、动态执行和 AI Provider 均通过适配器隔离；
- 默认本地运行，无强制 Web 服务或数据库。

### 4.3 非目标

首期不建设：Web UI、多租户、分布式调度、通用进程内跨语言 ABI、完整反编译器、默认执行目标 ELF。PostgreSQL/Neo4j 等服务端基础设施不是 CLI 核心依赖。

## 5. 用户场景

### 5.1 浏览产品能力

```bash
soinsight modules list
soinsight modules show basic
```

### 5.2 单项分析

```bash
soinsight basic elf libfoo.so
soinsight advanced strings libfoo.so
soinsight security hardening libfoo.so
soinsight dynamic trace libfoo.so
soinsight ai function-name libfoo.so
soinsight automation fuzz-target libfoo.so
```

### 5.3 跨域组合

```bash
soinsight scan libfoo.so --module basic,security --format json
soinsight scan libfoo.so --enable basic.elf,security.hardening
soinsight scan libfoo.so --profile security
```

### 5.4 多目标和自动化

```bash
soinsight automation binary-diff old.so new.so
soinsight automation workflow workflow.toml
```

多目标和 Workflow 当前仅定义外部形态，需在实现阶段扩展 Request 模型。

### 5.5 CI

```bash
soinsight scan libfoo.so \
  --profile ci \
  --format json \
  --no-color \
  --output result.json
```

风险阈值、基线抑制和 CI Gate 属于 `automation.workflow` 后续能力。

## 6. 命令体系

```text
soinsight
├── scan TARGET                 跨域组合扫描
├── basic                       基础分析
│   ├── file TARGET
│   ├── elf TARGET
│   ├── symbols TARGET
│   ├── dwarf TARGET
│   ├── types TARGET
│   ├── cpp TARGET
│   ├── disasm TARGET
│   ├── cfg TARGET
│   ├── callgraph TARGET
│   └── dataflow TARGET
├── advanced                    高级分析
│   ├── strings TARGET
│   ├── constants TARGET
│   ├── algorithm TARGET
│   ├── protocol TARGET
│   ├── file-format TARGET
│   ├── library TARGET
│   ├── compiler TARGET
│   └── obfuscation TARGET
├── security                    安全分析
│   ├── hardening TARGET
│   ├── dangerous-api TARGET
│   ├── vulnerability TARGET
│   └── risk TARGET
├── dynamic                     动态分析
│   ├── trace TARGET
│   ├── arguments TARGET
│   ├── memory TARGET
│   ├── syscalls TARGET
│   └── coverage TARGET
├── ai                          AI 分析
│   ├── function-name TARGET
│   ├── parameter-semantics TARGET
│   ├── struct-recovery TARGET
│   ├── module-identification TARGET
│   ├── algorithm-explanation TARGET
│   ├── protocol-explanation TARGET
│   ├── vulnerability-explanation TARGET
│   └── assembly-explanation TARGET
├── automation                  自动化
│   ├── binary-diff OLD NEW
│   ├── fuzz-target TARGET
│   ├── harness TARGET
│   ├── seed TARGET
│   ├── crash-cluster TARGET
│   ├── report TARGET
│   └── workflow TARGET
├── modules {list|show}         产品能力目录
├── plugins list               技术 Analyzer 注册表
├── report INPUT               基础结果转换入口
├── doctor                     环境检查
├── cache info                 缓存管理入口
└── config {create|list|show|validate|use|current|clear|set|unset}
```

### 6.1 命令稳定性

- 领域命令和 namespaced capability ID 是 canonical API；
- 旧扁平命令只作为开发期隐藏别名；
- `modules` 反映产品目录，`plugins` 反映实际加载的技术实现；
- 能力存在于目录中不等于实现已经注册。

### 6.2 退出码

| 码 | 含义 |
|---:|---|
| 0 | 成功 |
| 1 | 规划中的风险阈值不通过 |
| 2 | 参数、目标、配置或输入错误 |
| 3 | 能力未实现、Analyzer 缺失或计划错误 |
| 4 | Runtime 整体失败 |
| 5 | Runtime 部分成功 |

## 7. 总体架构

```text
┌─────────────────────────────────────────────────────────────┐
│ Product Capability Layer                                    │
│ Basic │ Advanced │ Security │ Dynamic │ AI │ Automation     │
│ ModuleCatalog / CapabilityDefinition / stable IDs            │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ CLI + Application Orchestration                             │
│ Commands │ TargetResolver │ Request │ Profile │ Response     │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ Shared Technical Core                                      │
│ Analyzer Registry │ DAG Planner │ Scheduler │ Rule Engine    │
│ Context │ Result Model │ Aggregator                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ Infrastructure / Providers                                 │
│ ToolRunner │ ArtifactStore │ PluginLoader │ Dynamic Sandbox  │
│ AI Provider │ Disassembler Adapter │ Serialization           │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ Renderers / Integrations                                   │
│ Text │ JSON │ Markdown │ HTML │ SARIF │ CI                  │
└─────────────────────────────────────────────────────────────┘
```

### 7.1 双视图原则

产品能力视图对用户稳定；技术实现视图可演进。例如 `security.dangerous-api` 可由 Symbol Analyzer、Disassembly Analyzer、Call Graph Analyzer 和多个 Rule 共同实现，但产品上仍是一项安全分析能力。

### 7.2 产品目录

`ModuleCatalog` 是产品能力的单一注册表，负责模块顺序、名称、描述、能力 ID、命令和输入形态。目录不持有 Analyzer 实例。

### 7.3 应用编排

Application 层把命令请求转换为一个分析计划：目标解析、模块展开、Profile 合并、能力去重、配置加载、Runtime 调用和响应渲染。

### 7.4 共享技术核心

核心层不理解 CLI 菜单，而是围绕稳定 ID 执行：注册、依赖解析、调度、上下文共享、Rule、状态聚合和诊断。

### 7.5 关键设计模式

V2 不为了“使用模式而使用模式”，而是用一组边界清晰的模式解决扩展、组合和隔离问题。

| 设计模式 | 在 SOInsight 中的落点 | 解决的问题 |
|---|---|---|
| 模块化单体（Modular Monolith） | 单一 `soinsight` 进程、六大产品能力域、共享 Core | 首期保持部署简单，同时避免所有能力混在一个包中 |
| 分层架构（Layered Architecture） | Product → CLI/Application → Core → Infrastructure → Renderer | 约束依赖方向，防止 CLI、业务实现和外部工具耦合 |
| 六边形架构（Ports and Adapters） | Analyzer/Store/Provider 为端口，ToolRunner/AI/动态沙箱为适配器 | 隔离 pyelftools、LIEF、Frida、LLM 等可替换技术 |
| 命令模式（Command） | 每个 CLI capability 转换为 AnalysisRequest | 让单项命令、Profile、Workflow 复用同一执行入口 |
| 注册表模式（Registry） | ModuleCatalog、AnalyzerRegistry、RuleRegistry、RendererRegistry | 发现实现并避免在 CLI 中硬编码实例 |
| 策略模式（Strategy） | Renderer、Scheduler、AI Provider、缓存和风险策略 | 根据配置替换算法而不改变调用方 |
| 模板方法（Template Method） | Analyzer 生命周期和统一错误/计时包装 | 统一执行规范，同时允许能力实现差异 |
| 责任链/流水线（Pipeline） | TargetResolver → Planner → Scheduler → Rule → Aggregator → Renderer | 让一次分析的处理阶段清晰且可测试 |
| 有向无环图（DAG） | Analyzer `requires` 和 Planner | 自动补全跨域依赖、检测循环并支持并发 |
| 仓储模式（Repository） | ArtifactStore | 隔离文件系统、SQLite 或远端 Artifact 存储 |
| 适配器模式（Adapter） | V1 Compatibility、外部反汇编器、动态工具、AI Provider | 复用旧实现和第三方能力，不污染核心模型 |
| 空对象模式（Null Object） | 空 PluginLoader、空 Registry、可选 Provider | 框架阶段保持链路可运行并返回明确诊断 |

#### 7.5.1 模式使用边界

- 产品模块不是 Python 类继承体系，不为六大领域建立巨型基类；
- Analyzer 与 capability 默认一一映射，但允许一个 capability 由多个内部实现协作；
- Strategy/Adapter 的替换必须保持统一结果契约；
- DAG 只表达数据依赖，不承载任意业务脚本；复杂条件编排归 `automation.workflow`；
- Repository 不泄漏具体数据库对象到 Core；
- 兼容适配器只能位于边界，V1 模型不得反向进入 V2 Core。

#### 7.5.2 核心对象协作

```text
CLI Command
  └── Command Handler
      └── AnalysisRequest
          └── AnalysisService
              ├── ModuleCatalog / ProfileRegistry
              └── AnalysisRuntime
                  ├── AnalyzerRegistry
                  ├── DependencyPlanner (DAG)
                  ├── Scheduler (Strategy)
                  ├── RuleEngine
                  ├── ArtifactStore (Repository Port)
                  └── ResultAggregator
                      └── Renderer (Strategy)
```

该协作关系保证同一个能力既可由 CLI 单独执行，也可被 Profile、Workflow、未来 API 或 GUI 复用。

## 8. Analyzer 模型

Analyzer 是内部最小执行单元，不是产品模块。

```python
class Analyzer(ABC):
    metadata: AnalyzerMetadata

    @abstractmethod
    def analyze(self, target, context) -> AnalysisResult:
        ...
```

```python
AnalyzerMetadata(
    id="basic.elf",
    name="ELF Parsing",
    version="1.0.0",
    requires=("basic.file",),
)
```

要求：

- ID 使用模块命名空间；
- 依赖显式声明；
- 从 Context 读取依赖结果；
- 返回统一结果；
- 不直接打印、不决定退出码；
- 不直接调用另一个 Analyzer；
- 外部工具调用走 ToolRunner；
- 结果字段和版本可测试。

Analyzer 可按技术职责标记 Collector、Transformer、Detector、Assistant 等 kind，但该分类仅用于实现管理。

## 9. Rule 模型

Rule 消费已采集事实并形成 Finding。适合可配置、可审计和可单独版本化的判断，例如危险 API、缺失保护、漏洞模式和风险策略。

```text
Analyzer: “观察到了什么”
Rule:     “这些事实意味着什么风险”
Renderer: “如何展示”
AI:       “如何基于证据解释”
```

不是所有安全能力都必须完全由 Rule 实现；复杂漏洞分析可以由 Analyzer 形成候选，再由 Rule 进行策略判断。

## 10. 依赖与任务编排

典型 DAG：

```text
basic.file
└── basic.elf
    ├── basic.symbols
    ├── basic.dwarf ── basic.types ── basic.cpp
    ├── security.hardening
    └── basic.disasm
        ├── basic.cfg ── basic.dataflow
        └── basic.callgraph

advanced.strings ─┬─ advanced.algorithm
advanced.constants┘

basic.symbols + basic.disasm + basic.callgraph
└── security.dangerous-api
    └── security.vulnerability
        ├── security.risk
        └── ai.vulnerability-explanation

advanced.protocol + basic.types + dynamic.coverage
└── automation.harness
```

规则：

- 必需依赖成功后运行下游；
- 可选依赖失败时允许降级；
- 无依赖分支可并发；
- 单项失败不阻断无关分支；
- Planner 检测缺失与循环；
- 跨域依赖只通过稳定 ID 和 Context；
- Workflow 可组合多个计划，但不复制分析逻辑。

## 11. Target 与 Request 模型

### 11.1 单目标

当前 `AnalysisTarget` 包含路径、真实路径、文件名、大小、SHA-256 等，适用于大部分静态能力。

### 11.2 多目标

Binary Diff 需要 `TargetSet` 或专用 `DiffRequest`：

```text
DiffRequest
├── old: AnalysisTarget
├── new: AnalysisTarget
├── scope
└── matching/options
```

不得将两个路径强行编码进单目标 Analyzer 的非标准字段。

### 11.3 动态目标

动态分析 Request 还需包含平台/ABI、设备或沙箱、启动方式、参数、环境、超时、授权证明和采集策略。

### 11.4 结果输入

AI、报告和 Crash 聚类可接受已有 `ScanResult`/Artifact，而不一定重新接受 ELF 文件。后续 CapabilityDefinition 应从简单参数名演进为可校验 InputSpec。

## 12. 统一结果与 IR

### 12.1 AnalysisResult

建议字段：Analyzer ID/版本、状态、开始结束时间、数据、Finding、Diagnostic、Artifact 引用、输入摘要和 Schema 版本。

### 12.2 Finding

包括 Rule ID/版本、标题、类别、严重度、置信度、消息、证据位置、影响、修复建议、关联函数/地址和抑制信息。

### 12.3 Unified Binary IR

```text
Binary
├── Module
├── Function
│   ├── BasicBlock
│   ├── Instruction
│   ├── Operand
│   ├── Parameters / Variables / Types
│   └── SourceLocation
├── CFG / CallGraph / DataFlow
├── Symbol / Relocation / Section / Segment
├── Library / Resource
├── Protocol / Algorithm
├── Security Finding
└── Runtime Trace / Coverage
```

IR 应渐进建设：先固化稳定事实结构，再抽取共享实体；避免在没有真实 Analyzer 前设计一个无法验证的庞大数据库模型。

## 13. Artifact Store 与缓存

缓存键至少包含：

```text
Target SHA-256
+ Analyzer ID/version
+ normalized config
+ dependency result versions
+ external tool/provider version
+ schema version
```

缓存必须支持原子写入、完整性校验、失效、查询和清理。动态结果还要包含环境/设备身份，AI 结果包含模型和提示版本。

## 14. Profile 与 Workflow

Profile 是声明式能力集合：

- `quick`：快速基础事实；
- `security`：安全能力及必要依赖；
- `deep`：基础 + 高级静态分析；
- `dynamic`：显式授权的动态采集；
- `ci`：稳定、受预算约束、可门禁。

Workflow 比 Profile 更高一级，可描述多目标、阶段、条件、基线、报告、发布和 CI Gate。Profile 选择“分析什么”，Workflow 定义“完整流程如何运行”。

## 15. 六大功能模块

### 15.1 基础分析

1. 文件分析 — `basic.file`
2. ELF 解析 — `basic.elf`
3. Symbol 解析 — `basic.symbols`
4. DWARF 解析 — `basic.dwarf`
5. 类型恢复 — `basic.types`
6. C++ 恢复 — `basic.cpp`
7. 反汇编 — `basic.disasm`
8. CFG 恢复 — `basic.cfg`
9. Call Graph 恢复 — `basic.callgraph`
10. Data Flow 分析 — `basic.dataflow`

边界：提供可复用事实和 IR，不承担最终风险解释。

### 15.2 高级分析

11. 字符串分析 — `advanced.strings`
12. 常量分析 — `advanced.constants`
13. 算法识别 — `advanced.algorithm`
14. 协议识别 — `advanced.protocol`
15. 文件格式识别 — `advanced.file-format`
16. 第三方库识别 — `advanced.library`
17. 编译器识别 — `advanced.compiler`
18. 混淆识别 — `advanced.obfuscation`

边界：从基础事实恢复高层语义；结论需保留证据和置信度。

### 15.3 安全分析

19. 安全保护检测 — `security.hardening`
20. 危险 API 检测 — `security.dangerous-api`
21. 漏洞模式识别 — `security.vulnerability`
22. 风险评分 — `security.risk`

边界：形成 Finding 和风险结论；不重复实现基础解析。

### 15.4 动态分析

23. Runtime Trace — `dynamic.trace`
24. 参数采集 — `dynamic.arguments`
25. 内存分析 — `dynamic.memory`
26. 系统调用分析 — `dynamic.syscalls`
27. 覆盖率分析 — `dynamic.coverage`

边界：只有在显式授权和隔离策略满足时执行；输出关联静态 IR。

### 15.5 AI 分析

28. 函数命名 — `ai.function-name`
29. 参数语义恢复 — `ai.parameter-semantics`
30. 结构体恢复 — `ai.struct-recovery`
31. 模块识别 — `ai.module-identification`
32. 算法解释 — `ai.algorithm-explanation`
33. 协议解释 — `ai.protocol-explanation`
34. 漏洞解释 — `ai.vulnerability-explanation`
35. 汇编自然语言解释 — `ai.assembly-explanation`

边界：AI 是证据驱动的辅助层，不覆盖确定性事实；结果记录 Provider、模型、提示版本、输入引用和置信度。

### 15.6 自动化

36. Binary Diff — `automation.binary-diff`
37. Fuzz Target 识别 — `automation.fuzz-target`
38. Harness 生成 — `automation.harness`
39. Seed 生成 — `automation.seed`
40. Crash 聚类 — `automation.crash-cluster`
41. 报告自动化 — `automation.report`（优化补充）
42. 工作流自动化 — `automation.workflow`（优化补充）

边界：组合其他领域的标准结果，负责可复现流程，不复制底层分析器。

## 16. 输出与报告

首期稳定格式为 Text 和 JSON。后续支持 Markdown、HTML、SARIF、GraphML/GEXF。

报告需要：目标身份、工具和 Schema 版本、执行配置、能力状态、Finding、Diagnostic、证据引用、Artifact、耗时和不完整性说明。

顶层 `report` 是基础结果转换入口；`automation.report` 是产品级报告流水线，后续可编排模板、归档、签名、发布和多目标汇总。

## 17. YAML 配置系统

### 17.1 目标与边界

YAML Config 是用户可管理的“分析策略对象”，统一描述：选择哪些六大模块、模块中的哪些 capability、跨模块补充/排除、Runtime、输出和能力专属参数。它不把具体技术重新分类为一级模块，也不替代 Profile 或 Workflow。

- **Profile**：由核心或插件发布的稳定能力集合；
- **YAML Config**：用户/项目订制的单目标分析策略；
- **Workflow**：未来多目标、多阶段、条件、基线、CI Gate 和发布编排。

Workflow 可以引用 YAML Config，YAML Config 可以引用 Profile，但三者生命周期和职责分离。

### 17.2 Schema v1

```yaml
schema_version: 1
name: quick-security
description: Quick security policy
analysis:
  modules:
    basic: [file, elf, symbols]
    security: [hardening]
  capabilities: [advanced.strings]
  exclude: [basic.symbols]
  # profile: quick
runtime:
  jobs: 1
  timeout_seconds: 60
  cache_enabled: true
  cache_dir: .soinsight/cache
  fail_fast: false
  quiet: false
  verbose: false
  no_color: false
output:
  format: text
  # path: result.json
capability_options:
  advanced.strings:
    min_length: 4
  security.risk:
    threshold: high
```

规则：

1. `analysis.modules.<module>` 使用模块内 command；值为列表或带引号的 `"*"`；
2. `analysis.capabilities`/`exclude` 使用完整 `<module>.<capability>` ID；
3. 当前单目标 Runtime 拒绝 `automation.binary-diff` 等多目标能力；
4. `capability_options` 以完整 capability ID 为键，经 `RuntimeConfig.extra` 传递；
5. 未知模块、能力、Runtime/Output 字段、非法类型和不兼容目标形态在执行前失败；
6. `schema_version` 为演进边界，不允许静默接受未知版本。

### 17.3 配置仓库与命令模式

`YamlConfigStore` 是 Config Repository：负责解析托管名称/外部路径、读取、完整 Schema 校验、原子保存、列表和活动配置指针。默认托管目录为 `~/.config/soinsight/configs`，可由 `SOINSIGHT_CONFIG_DIR` 或 `config --config-dir` 覆盖；活动指针保存在托管目录上一级 `active-config`。

```text
soinsight config create NAME [--force]
soinsight config list
soinsight config show NAME_OR_PATH
soinsight config validate NAME_OR_PATH
soinsight config use NAME_OR_PATH
soinsight config current
soinsight config clear
soinsight config set NAME_OR_PATH KEY YAML_VALUE
soinsight config unset NAME_OR_PATH KEY
```

`set/unset` 使用 dotted key，值按 YAML 标量/列表/映射解析。修改流程为“读取 → 修改内存映射 → 完整校验 → 临时文件 → 原子替换”，验证失败不得破坏原配置。规范化写回不承诺保留注释。

### 17.4 解析和合并算法

```text
explicit --config → managed name / external path
        ↓ absent
active-config pointer
        ↓ absent
no YAML config
```

综合 `scan` 的能力选择顺序：

1. YAML Profile；
2. YAML modules/capabilities；
3. CLI Profile、`--module`、`--enable`；
4. 去重；
5. 应用 YAML `exclude`；
6. 若此前完全没有选择，使用 Registry defaults。

显式领域命令（如 `basic elf TARGET --config NAME`）始终只请求 `basic.elf`，但复用 YAML Runtime、Output 和 `capability_options`。

运行和输出优先级为：

```text
显式 CLI > 显式/活动 YAML > Runtime 默认值
```

YAML 配置名、来源和 capability options 进入 `RuntimeConfig.extra`。未来缓存键必须包含规范化选择、影响结果的 Runtime 字段、能力参数、Analyzer/工具版本，避免不同策略错误命中同一缓存。

### 17.5 安全与演进

配置文件不得直接持久化 API Key、Token 和密码；敏感凭据应由环境变量、Keyring 或 CI Secret 注入。AI Provider、动态沙箱和 CI Policy 可在后续 Schema 版本扩展，但必须有迁移器、兼容测试和脱敏规则。项目级自动发现配置尚未启用，避免不可信仓库在用户无感知时改变动态/AI 行为。

## 18. 安全边界

### 18.1 静态分析

- 默认不执行目标；
- 外部工具使用参数数组和超时；
- 限制输出大小、递归深度和资源；
- 所有目标内容和工具输出视为不可信。

### 18.2 动态分析

- 必须显式选择动态命令/Profile；
- 使用容器、虚拟机或受控设备；
- 限制网络、文件系统、权限、CPU、内存和时间；
- 清理进程与临时文件；
- 报告环境、风险和隔离级别。

### 18.3 AI

- 默认不上传二进制和敏感字符串；
- Provider 需声明本地/远程、数据保留和成本；
- 防止目标内容成为未隔离 Prompt 指令；
- 输出必须引用输入证据并标记推断；
- 支持关闭、脱敏、预算和审计。

## 19. 非功能要求

- Python 3.10+；
- Linux 优先，Android ELF 为核心目标；
- JSON 输出确定性和 Schema 兼容；
- 相同目标/配置/工具版本可复现；
- 单项失败结构化且不导致无关分支崩溃；
- 大文件、工具超时和输出爆炸受控；
- 日志不污染 JSON stdout；
- 每项结果可追溯到能力、实现和依赖版本。

## 20. 测试策略

### 20.1 单元测试

ModuleCatalog 校验、DAG、状态聚合、Rule、配置、序列化、缓存键和输入规范。

### 20.2 集成测试

领域 CLI、模块展开、Analyzer 注册、外部工具失败、Text/JSON、退出码、Wheel 入口。

### 20.3 Golden Test

维护最小 ELF、不同 ABI、损坏/截断、带/不带 DWARF、C++、保护开关、混淆和真实开源样本；比较结构化字段，不依赖易变终端文本。

### 20.4 安全测试

恶意路径、超大输出、工具挂起、压缩炸弹式输入、动态逃逸、Prompt Injection、秘密泄露和资源耗尽。

## 21. Roadmap

### Phase 1A：产品外壳与共享框架（已完成）

- 六大模块与 42 项能力目录；
- 领域 CLI、`modules`、`scan --module`（仅展开单目标兼容能力）；
- Analyzer/Rule/Profile/Renderer SDK；
- DAG Planner、串行 Scheduler、统一模型；
- Wheel 构建和 14 项自动化测试。

### Phase 1B：首条真实跨域链路

`basic.file → basic.elf → security.hardening → Finding → JSON`。

### Phase 1C：迁移 V1

`basic.symbols`、`advanced.strings`、`security.dangerous-api`、`security.risk`，以及 URL/Secret/Base64/JNI 规则。

### Phase 2：共享工程能力

Schema、Profile、缓存、报告、插件发现、并发、日志与 Golden 样本。

### Phase 3：基础分析深化

DWARF、类型、C++、反汇编、CFG、Call Graph、Data Flow。

### Phase 4：高级与安全分析

算法、协议、格式、库、编译器、混淆；漏洞模式、证据链、风险评分和 CI Policy。

### Phase 5：动态分析

先交付沙箱与授权模型，再交付 Trace、参数、内存、系统调用和覆盖率。

### Phase 6：AI 分析

Provider 治理、证据引用、命名/恢复和解释能力；AI 始终可选。

### Phase 7：自动化

Binary Diff、Fuzz、Crash、报告流水线、批处理和 CI Gate。

Roadmap 按交付依赖推进，但每项能力始终归属六大产品模块，不再以技术组件作为一级功能分类。

## 22. 推荐技术方向

| 能力 | 可选技术 |
|---|---|
| ELF | pyelftools、LIEF、libelf/ELFIO |
| DWARF | pyelftools、libdwarf、LLVM DWARF |
| 反汇编 | Capstone、LLVM MC、Ghidra/RetDec 适配器 |
| 图分析 | NetworkX 或自定义紧凑图模型 |
| 动态 | Frida、QBDI、DynamoRIO、Android 受控设备 |
| Fuzz | libFuzzer、AFL++、Honggfuzz 适配器 |
| AI | 本地/远程可插拔 Provider + RAG（可选） |
| 存储 | 文件 Artifact Store 起步，按需扩展 SQLite |

技术选择必须通过适配器接入，不能成为产品模块边界。

## 23. 配套文档

```text
docs/
├── README.md
├── getting-started.md
├── user-guide.md
├── cli-reference.md
├── module-system.md
├── architecture.md
├── extension-development.md
├── migration-v1-to-v2.md
└── project-status.md
```

后续按需要增加：结果 Schema、IR、动态沙箱、AI Provider、安全模型、Workflow 格式、各能力 SDS。

## 24. 待决策事项

1. CapabilityDefinition 的 InputSpec/OutputSpec 结构；
2. Binary Diff 的多目标 Runtime 边界；
3. Analyzer 与 Capability 是一对一还是允许显式多实现；
4. optional dependency 调度语义；
5. 内置 Profile 的稳定集合；
6. JSON Schema 版本策略；
7. 插件发现、签名和 API 兼容策略；
8. 动态隔离等级；
9. AI 默认 Provider、隐私与预算策略；
10. 风险评分、基线抑制和 CI 退出码。

## 25. 当前实现基线

截至 2026-08-04：

**已经实现**：

- `src/soinsight/modules/` 六大产品模块；
- 42 项能力定义、命名空间和 Catalog 校验；
- 领域化 CLI 命令树；
- `modules list/show`；
- `scan --module`（仅展开单目标兼容能力）；
- 单目标能力到 Runtime 路由；
- Analyzer/Rule/Profile/Renderer、DAG、Scheduler、统一结果；
- 构建脚本和 14 项测试。

**尚未实现**：

- 42 项能力对应的真实 Analyzer/Rule/Provider；
- 双目标和复杂输入 Runtime；
- 内置 Profile、真实缓存、并发和插件发现；
- 动态沙箱、AI Provider 和自动化工作流；
- Markdown/HTML/SARIF 和完整 Schema。

因此当前阶段的准确描述是：**SOInsight V2 已完成以六大能力域为中心的 CLI 外部框架和共享技术底座，下一步进入真实分析能力迁移。**
