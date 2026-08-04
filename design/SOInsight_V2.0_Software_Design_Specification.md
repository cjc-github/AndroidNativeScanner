# SOInsight V2.0 CLI 工具箱总体设计

> 面向 Linux/Android ELF 动态库的模块化分析工具箱

## 1. 文档信息

| 项目 | 内容 |
|---|---|
| 文档版本 | 2.1 |
| 文档状态 | 总体设计（框架基线已实现，业务能力持续建设） |
| 更新日期 | 2026-08-04 |
| 当前实现基线 | Android Native Scanner V1 + SOInsight V2 Framework `2.0.0.dev0` |
| 历史版本 | SOInsight V1（旧版规划） |
| 目标形态 | 本地优先、可组合、可扩展的 CLI 工具箱 |

## 2. 版本演进

SOInsight V2 基于现有 Android Native Scanner 演进。仓库当前同时存在两条实现线：

**Android Native Scanner V1（现有业务能力）**：

- ELF Header 基础信息分析；
- 动态符号扫描；
- 字符串提取与统计；
- URL、敏感信息、Base64 和 JNI 检测；
- 单文件及目录批量扫描；
- 文本报告和基础风险汇总；
- 基于 `BaseAnalyzer` 和 `AnalysisCoordinator` 的分析器组织方式。

**SOInsight V2（当前框架基线）**：

- 独立 `soinsight` CLI 包和命令树；
- Analyzer、Rule、Profile、Renderer 扩展接口；
- Analyzer Registry、依赖 DAG Planner 和串行 Scheduler；
- 统一 Target、Result、Finding 和 Diagnostic 模型；
- Text/JSON Renderer、ToolRunner、ArtifactStore 等基础边界；
- 框架级单元测试和 CLI 集成测试。

截至 2026-08-04，V2 尚未迁移具体 ELF Analyzer。V1 继续承担现有扫描功能，V2 负责建立新架构并逐步接入能力。SOInsight V1 规划文档仅作为历史参考。V2 不直接建设大型 Web 分析平台，而是优先将现有项目升级为统一、模块化的 CLI 工具箱。

## 3. 项目定位

SOInsight V2 是一个面向 Linux/Android ELF 动态库（主要为 `.so` 文件）的模块化 CLI 分析工具箱，主要服务于：

- 原生库基础信息检查；
- Android Native 安全审计；
- ELF 逆向分析辅助；
- 版本差异分析；
- 自动化脚本和 CI 集成；
- 后续 AI、动态分析和 Fuzz 能力扩展。

用户可以通过独立子命令运行单项分析，也可以使用 `scan` 命令按 Profile 或分析器列表执行组合分析，并生成统一结果和报告。

## 4. 设计目标

### 4.1 核心目标

- **工具箱化**：每项能力均可通过独立 CLI 子命令调用；
- **可组合**：`scan` 命令可组合多个分析器并复用中间结果；
- **模块化**：分析逻辑与 CLI 参数解析、报告渲染相互分离；
- **可扩展**：支持通过稳定接口增加分析器、检测规则和输出格式；
- **本地优先**：默认无需 Web 服务和外部数据库即可运行；
- **结果统一**：统一分析结果、Finding、诊断信息和版本字段；
- **安全可控**：默认不执行被分析文件，外部工具具备超时和资源限制；
- **自动化友好**：提供稳定 JSON、退出码、风险阈值和无颜色输出。

### 4.2 非目标

SOInsight V2.0 首期不包含：

- Web UI；
- 多租户和用户权限系统；
- 分布式任务调度；
- PostgreSQL、Neo4j 等服务端基础设施；
- 通用的进程内跨语言插件 ABI；
- 默认执行目标 ELF；
- 完整反编译器实现。

Web、REST API、服务端存储和企业级能力可作为后续独立项目或包装层，不进入 V2 CLI 核心。

## 5. 使用场景

### 5.1 单项分析

```bash
soinsight elf libfoo.so
soinsight symbols libfoo.so
soinsight strings libfoo.so
soinsight security libfoo.so
```

适合快速查看某类信息、脚本调用和问题排查。

### 5.2 综合扫描

```bash
# 当前框架支持单文件目标
soinsight scan libfoo.so
soinsight scan libfoo.so --format json --output result.json

# 目录递归扫描属于后续规划，当前尚未实现
# soinsight scan ./libs --recursive --jobs 4 --output ./reports
```

综合扫描负责按依赖关系执行多个分析器，共享 ELF、符号、字符串等中间结果，并生成统一报告。当前框架链路已可运行，但尚无内置业务 Analyzer。

### 5.3 精确选择分析器

```bash
# 当前已支持 --enable；所选 Analyzer 必须已经注册
soinsight scan libfoo.so --enable elf,symbols,strings,security

# --disable 尚未实现，属于后续规划
# soinsight scan libfoo.so --disable dwarf,disasm,cfg,ai
```

### 5.4 CI 集成

```bash
# 当前可用的自动化输出方式
soinsight scan libfoo.so \
  --format json \
  --no-color \
  --output result.json

# --fail-on 风险阈值属于后续规划
```

### 5.5 从已有结果生成报告

```bash
# 当前 report 只读取、验证 JSON 语法并重新格式化
soinsight report result.json --format json --output normalized.json

# HTML/Markdown/SARIF 报告属于后续规划
```

## 6. 命令体系

```text
soinsight
├── scan               综合扫描
├── file               文件指纹、Magic、熵和基础属性
├── elf                ELF Header、Section、Segment、Dynamic 等
├── symbols            导入、导出和版本化符号
├── strings            字符串提取、过滤和分类
├── dwarf              DWARF 调试信息
├── disasm             反汇编和函数边界识别
├── cfg                控制流图
├── callgraph          调用图
├── security           安全保护和安全规则检测
├── identify           算法、第三方库、编译器、协议等识别
├── diff               Binary Diff
├── dynamic            可选的隔离动态分析
├── fuzz               Fuzz Target、Harness 和 Crash 辅助
├── ai                 可选的 AI 语义辅助
├── report             报告生成和格式转换
├── plugins            插件查看和管理
├── cache              本地缓存查看和清理
├── config             配置查看和校验
└── doctor             环境、依赖和工具版本检查
```

### 6.1 高级命令规划示例

以下形式用于定义未来命令空间，当前 CLI 仅保留 `identify`、`diff`、`ai`、`fuzz` 等一级占位命令，尚未实现这些二级命令：

```bash
soinsight identify library libfoo.so
soinsight identify algorithm libfoo.so
soinsight identify compiler libfoo.so

soinsight security hardening libfoo.so
soinsight security secrets libfoo.so
soinsight security scan libfoo.so

soinsight diff binary old.so new.so
soinsight diff functions old.so new.so

soinsight ai explain libfoo.so --function 0x1234
soinsight fuzz targets libfoo.so
```

### 6.2 参数状态

当前 CLI 已接受：

| 参数 | 当前说明 |
|---|---|
| `--format` | 当前支持 `text`、`json` |
| `-o, --output` | 输出文件，`-` 表示 stdout |
| `-j, --jobs` | 已进入配置，Scheduler 当前仍串行 |
| `--timeout` | 已进入配置，具体 Analyzer 应传递给外部工具 |
| `-q, --quiet` | 已保留配置入口，完整日志策略待实现 |
| `-v, --verbose` | 已保留配置入口，完整日志策略待实现 |
| `--no-color` | 已保留配置入口 |
| `--cache-dir` | 已进入配置，Runtime 缓存尚未接入 |
| `--no-cache` | 已进入配置，Runtime 缓存尚未接入 |
| `--fail-fast` | 已进入配置，Scheduler 行为尚未接入 |

规划参数：

| 参数 | 规划说明 |
|---|---|
| `-c, --config` | 配置文件路径 |
| `--log-level` | 日志级别 |
| `--force` | 忽略缓存并重新分析 |
| `--keep-temp` | 保留临时分析文件 |
| `--fail-on` | Finding 风险阈值 |

### 6.3 退出码

当前实现：

| 退出码 | 含义 |
|---:|---|
| 0 | 命令或扫描框架成功 |
| 2 | 参数、目标、配置或报告输入错误 |
| 3 | 分析计划错误、Analyzer 缺失或占位命令未实现 |
| 4 | 分析任务整体失败 |
| 5 | 部分分析器失败，已生成降级结果 |

目标设计还将增加退出码 `1`，用于表示命令执行成功但 Finding 达到 `--fail-on` 阈值。“发现风险”和“工具执行失败”必须使用不同退出码。

## 7. 总体架构

```text
                         SOInsight CLI
                              │
              ┌───────────────┴───────────────┐
              │                               │
       Independent Commands              Scan Command
       独立分析子命令                     组合分析命令
              │                               │
              └───────────────┬───────────────┘
                              │
                       Analysis Runtime
         ┌────────────────────┼────────────────────┐
         │                    │                    │
   Command Registry      Dependency DAG      Analysis Context
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                       Analyzer Registry
   ┌─────────┬────────┬───────┼────────┬──────────┬─────────┐
   │ ELF     │ Symbol │ String│ CFG    │ Security │ Diff    │
   │ DWARF   │ Disasm │ AI    │ Fuzz   │ Dynamic  │ Report  │
   └─────────┴────────┴───────┴────────┴──────────┴─────────┘
                              │
              Result Model / Local Artifact Store
                              │
                 Text / JSON / Markdown / HTML
```

### 7.1 分层职责

#### CLI Layer

- 解析命令和参数；
- 加载配置；
- 调用 Analysis Runtime；
- 控制终端输出和退出码；
- 不直接实现 ELF 分析逻辑。

#### Analysis Runtime

- 分析器注册和查找；
- 依赖解析；
- 任务编排、并发、超时和取消；
- 上下文及中间结果共享；
- 缓存读写；
- 错误聚合和降级执行。

#### Analyzer Layer

- 从目标文件或依赖结果中提取事实；
- 产生结构化分析结果；
- 产生可选的 Finding、Warning 和 Error；
- 不直接负责终端排版和 HTML 生成。

#### Renderer Layer

- 将统一结果渲染为 Text、JSON、Markdown 或 HTML；
- 对不可信字符串执行必要的转义；
- 不重新执行分析逻辑。

#### Artifact Store

- 在本地保存可复用的中间结果；
- 支持缓存校验、查询和清理；
- V2 首期采用文件系统实现，数据库不是必需依赖。

## 8. 分析器模型

### 8.1 分析器分类

| 类型 | 职责 | 示例 |
|---|---|---|
| Collector | 从二进制提取事实 | ELF、Symbol、String、DWARF |
| Transformer | 将已有结果转换为高级模型 | Disassembly、CFG、CallGraph |
| Detector | 根据事实产生 Finding | Secret、Dangerous API、Hardening |
| Assistant | 产生辅助性推断 | AI 命名、算法解释 |
| Reporter | 渲染已有结果 | Text、JSON、HTML |

分析器分类用于说明职责，不要求首期建立复杂的类继承层次。

### 8.2 分析器接口

V2 在当前 `BaseAnalyzer.analyze()` 基础上演进，建议接口如下：

```python
class Analyzer(ABC):
    id: str
    name: str
    version: str
    description: str
    kind: str

    requires: tuple[str, ...] = ()
    optional_requires: tuple[str, ...] = ()

    @abstractmethod
    def analyze(
        self,
        target: "AnalysisTarget",
        context: "AnalysisContext",
    ) -> "AnalysisResult":
        ...
```

接口要求：

- `id` 在同一 API 版本内保持稳定；
- 分析器显式声明必需和可选依赖；
- 分析器从 `AnalysisContext` 获取依赖结果，不自行重复执行同一基础分析；
- 分析器返回统一 `AnalysisResult`；
- 分析器不得直接修改其他分析器结果；
- 分析器不得直接控制进程退出码；
- CLI、报告格式和风险汇总不应硬编码在分析器中。

### 8.3 注册方式

V2 首期支持：

1. 内置分析器静态注册；
2. Python Entry Point 或插件目录发现；
3. 通过配置启用和禁用插件。

V2 首期仅保证 Python 插件接口。Rust、C++ 和 Go 等语言后续通过进程外协议接入，避免在主进程中维护跨语言 ABI。

## 9. 依赖与任务编排

分析器执行顺序不应继续完全依赖硬编码列表，而应由依赖关系构建 DAG。

```text
File
├── Strings
└── ELF
    ├── Symbols
    ├── DWARF
    ├── Security Hardening
    └── Disassembly
        ├── CFG
        │   └── DataFlow
        └── CallGraph

Available Results
├── Security Rules
├── Identification
├── AI Assistant
└── Report
```

### 9.1 调度规则

- 必需依赖成功后才能运行当前分析器；
- 可选依赖失败时允许降级运行；
- 无依赖关系的任务可以并发执行；
- 单个模块失败默认不阻止无关模块；
- `--fail-fast` 可改变默认失败策略；
- 每个任务记录开始时间、结束时间、耗时和状态；
- 支持单任务超时和全局取消；
- 相同输入和配置可命中缓存；
- 最终报告必须包含未运行、跳过和失败模块的信息。

### 9.2 任务状态

```text
PENDING
RUNNING
SUCCESS
PARTIAL
SKIPPED
TIMEOUT
FAILED
CANCELLED
CACHED
```

## 10. 统一结果模型

V2 首期优先统一分析结果和安全 Finding，不要求所有基础分析器依赖完整反编译 IR。

### 10.1 AnalysisResult

```json
{
  "schema_version": "soinsight.result/v1",
  "tool_version": "2.0.0",
  "target": {
    "path": "libfoo.so",
    "sha256": "...",
    "size": 123456
  },
  "analyzer": {
    "id": "elf",
    "version": "2.0.0"
  },
  "status": "success",
  "duration_ms": 42,
  "data": {},
  "findings": [],
  "warnings": [],
  "errors": []
}
```

所有持久化结果必须包含：

- Schema 版本；
- 工具版本；
- 输入文件哈希；
- 分析器 ID 和版本；
- 配置摘要或配置哈希；
- 执行状态和耗时；
- 数据、Finding 和诊断信息。

### 10.2 Finding

```json
{
  "rule_id": "SI-SECRET-001",
  "title": "疑似硬编码访问令牌",
  "category": "secret",
  "severity": "high",
  "confidence": "medium",
  "message": "在只读数据中发现疑似访问令牌",
  "location": {
    "file_offset": 4096,
    "virtual_address": "0x101000"
  },
  "evidence": [],
  "remediation": "从二进制中移除凭据并使用安全配置注入。"
}
```

Finding 至少包含：

- 稳定规则 ID；
- 标题和分类；
- 严重程度；
- 置信度；
- 证据；
- 可选位置；
- 修复建议。

### 10.3 信息分类

结果分为三类：

1. **Information**：ELF 属性、字符串数量、JNI 方法等客观信息；
2. **Observation**：值得关注但尚不能证明存在漏洞的现象；
3. **Finding**：具备明确安全含义和证据的发现。

只有 Finding 参与总体风险等级计算。URL、JNI、符号和字符串数量不得直接按数量累加为高风险。

## 11. Binary IR 演进

完整 Binary IR 随反汇编、CFG 和 DataFlow 分阶段引入：

```text
Binary
├── ELF
│   ├── Section
│   ├── Segment
│   ├── Symbol
│   └── Relocation
├── Function
│   ├── BasicBlock
│   ├── Instruction
│   ├── Parameter
│   └── Variable
├── ControlFlowEdge
├── CallEdge
├── DataFlowEdge
├── Type
└── RuntimeObservation
```

IR 设计必须区分：

- 文件偏移；
- 虚拟地址；
- RVA；
- 静态加载基址；
- 运行时地址；
- 数据来源；
- 生产者及其版本；
- 推断置信度。

推断型字段应保存来源和证据，例如：

```json
{
  "value": "encrypt_packet",
  "source": "ai",
  "confidence": 0.73,
  "producer": "ai-function-namer",
  "producer_version": "1.0.0",
  "evidence": ["call:EVP_EncryptInit_ex"]
}
```

## 12. 本地缓存与 Artifact Store

默认缓存目录：

```text
.soinsight/
└── cache/
    └── <input-sha256>/
        ├── manifest.json
        ├── file.json
        ├── elf.json
        ├── symbols.json
        ├── strings.json
        ├── disassembly.json
        ├── cfg.json
        ├── callgraph.json
        └── findings.json
```

缓存有效性由以下信息共同决定：

- 输入文件 SHA-256；
- 分析器 ID 和版本；
- Result Schema 版本；
- 分析配置哈希；
- 必需依赖结果哈希；
- 外部工具版本（适用时）。

首期使用文件系统实现。SQLite 可作为后续本地索引，但分析器不得直接依赖具体存储后端。

## 13. 扫描 Profile

`scan` 支持预定义 Profile：

| Profile | 目标 | 默认能力 |
|---|---|---|
| `quick` | 快速信息收集 | File、ELF、Symbol、String |
| `default` | 日常综合扫描 | Quick + Hardening + Sensitive + Library ID |
| `security` | 安全审计 | Default + Disassembly + CFG + Security Rules |
| `reverse` | 逆向辅助 | ELF + DWARF + Disassembly + CFG + CallGraph + C++ |
| `deep` | 深度静态分析 | 除 Dynamic、Fuzz、AI 外的可用静态模块 |

示例：

```bash
soinsight scan libfoo.so --profile quick
soinsight scan libfoo.so --profile security
```

AI、动态分析和 Fuzz 默认不属于普通扫描流程，必须显式启用。

## 14. 功能模块规划

### 14.1 基础分析

- 文件哈希、Magic、大小和熵；
- ELF32/ELF64、端序、架构和 ABI；
- Header、Section、Segment、Dynamic、Relocation、TLS 和 Version；
- 导入、导出、Weak、Hidden、Local、Global 和 TLS Symbol；
- 字符串提取、编码识别和分类；
- DWARF 文件、变量、参数、结构体、类和命名空间。

### 14.2 代码分析

- 函数边界识别；
- 指令和操作数；
- Basic Block；
- CFG、Loop、Switch、Exception 和 Dominator；
- Caller/Callee、递归和热点函数；
- Use-Def、Alias、Pointer Flow；
- RTTI、vtable、继承关系、构造和析构函数。

### 14.3 识别能力

- 常量和 Magic Number；
- 加密、哈希、压缩、编码和序列化算法；
- OpenSSL、SQLite、protobuf、gRPC、FFmpeg 等第三方库；
- 编译器、文件格式、协议和混淆特征。

### 14.4 安全分析

- NX、RELRO、PIE、Canary、FORTIFY、CFI 和 PAC；
- 危险 API 的导入、调用点和可选数据流证据；
- 硬编码凭据和敏感配置；
- 漏洞模式规则；
- Finding 去重、严重程度、置信度和风险汇总。

### 14.5 高级可选能力

- Binary Diff；
- 隔离的 Runtime Trace、参数、内存、系统调用和覆盖率分析；
- AI 函数命名、参数语义、结构体辅助恢复和漏洞解释；
- Fuzz Target、Harness、Seed、Crash 聚类和复现辅助。

## 15. 风险模型

风险模型不再直接累计字符串、URL、Base64 或 JNI 的数量。

总体风险由 Finding 决定，至少考虑：

- Severity：`critical`、`high`、`medium`、`low`、`info`；
- Confidence：`high`、`medium`、`low`；
- Evidence Quality：符号、调用点、控制流、数据流或运行时证据；
- 去重后的 Finding 数量；
- 用户配置的规则权重和忽略项。

建议默认规则：

```text
Critical Finding 存在                    → CRITICAL
High Finding 存在                        → HIGH
无 High，但存在 Medium Finding           → MEDIUM
仅存在 Low/Info Finding                  → LOW
没有安全 Finding                         → NONE
```

数值分数仅作为排序和趋势比较的辅助字段，不应替代严重程度和证据说明。

## 16. 输出与报告

### 16.1 输出格式

V2 核心支持：

- Text：人类可读终端输出；
- JSON：稳定、版本化的机器输出；
- Markdown：便于审计记录；
- HTML：便于离线查看。

后续可选：

- PDF；
- GraphML；
- GEXF；
- SARIF。

### 16.2 报告要求

报告至少包含：

- 目标文件路径、大小和 SHA-256；
- SOInsight 和插件版本；
- 配置及 Profile；
- 各分析器状态和耗时；
- Information、Observation 和 Finding；
- 失败、超时、跳过和降级模块；
- 风险汇总；
- 生成时间和 Result Schema 版本。

HTML 报告必须转义来自目标文件的字符串、符号和其他不可信内容。

## 17. 配置系统

配置优先级从低到高：

1. 内置默认值；
2. 用户级配置；
3. 项目级配置；
4. `--config` 指定配置；
5. 环境变量；
6. CLI 参数。

配置示例：

```yaml
profiles:
  default:
    analyzers:
      - file
      - elf
      - symbols
      - strings
      - security-hardening
      - sensitive-data

runtime:
  jobs: 4
  timeout: 60
  cache: true

report:
  format: text
  show_info: true

security:
  fail_on: high
  disabled_rules: []
```

配置文件需要 Schema 校验，未知字段默认产生警告。

## 18. 安全边界

SOInsight 处理的 ELF 文件和其中所有内容均视为不可信输入。

### 18.1 静态分析

- 默认不加载、不链接、不执行目标 ELF；
- 外部命令使用参数数组调用，禁止拼接 Shell 命令；
- 设置超时、输出大小和资源限制；
- 临时目录按任务隔离；
- 日志和报告对控制字符及 HTML 内容进行转义；
- 解析器异常不得导致整个批量任务崩溃。

### 18.2 动态分析

- 默认关闭，用户必须显式启用；
- 只能在容器、虚拟机、模拟器或专用 Android 设备中运行；
- 限制文件系统、网络、进程和设备权限；
- 动态分析结果必须标明运行环境和观测条件。

### 18.3 AI 分析

- 默认关闭；
- 明确区分本地模型和远程模型；
- 发送到远程模型前提供数据出域提示和配置开关；
- ELF 字符串和反编译内容只能作为不可信数据，不能作为系统指令；
- AI 结果必须标记模型、Prompt 版本、置信度和证据；
- AI 推断默认不作为确定性漏洞证据。

## 19. 非功能要求

### 19.1 可移植性

目标支持矩阵：

- 主机：Linux，其他系统作为后续兼容目标；
- 文件：ELF32、ELF64；
- 端序：优先 Little Endian，Big Endian 按模块声明支持情况；
- 架构：ARM、AArch64、x86、x86_64；
- Android ABI：`armeabi-v7a`、`arm64-v8a`、`x86`、`x86_64`；
- 样本：stripped/unstripped、有/无 DWARF。

每个分析器应声明自己的支持范围，不能默认所有模块支持全部架构。

### 19.2 可复现性

持久化结果记录：

- 输入哈希；
- 工具和插件版本；
- 外部工具版本；
- 配置快照或配置哈希；
- Schema 版本；
- AI 模型和 Prompt 版本（适用时）。

### 19.3 可观测性

每个分析器至少记录：

- 状态；
- 耗时；
- 缓存命中情况；
- 结果数量；
- Warning 和 Error；
- 是否降级执行。

## 20. 测试策略

### 20.1 单元测试

- 分析器输入输出；
- Result/Finding Schema；
- CLI 参数和退出码；
- DAG 依赖解析；
- 缓存键和失效逻辑；
- 风险汇总与规则过滤。

### 20.2 集成测试

测试样本至少覆盖：

- ELF32/ELF64；
- ARM/AArch64/x86/x86_64；
- stripped/unstripped；
- 有/无 DWARF；
- C/C++ 动态库；
- Android NDK 产物；
- 损坏、截断和异常 ELF；
- 大型 Section、Symbol 和 String Table；
- 单个外部工具缺失、失败和超时。

### 20.3 Golden Test

对稳定样本保存预期 JSON，升级分析器或 Schema 时进行结构化差异比较，避免无意改变输出协议。

## 21. Roadmap

### Phase 1：CLI 框架与现有能力迁移

#### Phase 1A：外部框架骨架（已完成）

已交付：

- `soinsight` 主命令及预留命令树；
- Analyzer、Rule、Profile、Renderer SDK；
- 统一 Target、Result、Finding、Diagnostic；
- Analyzer Registry、依赖 DAG、串行 Scheduler；
- Text/JSON Renderer；
- ToolRunner、ArtifactStore、PluginLoader 边界；
- Python 包构建和框架测试。

#### Phase 1B：最小真实分析链路（下一阶段）

计划交付：

- `FileAnalyzer`；
- `ElfAnalyzer`；
- `quick` Profile；
- 非 ELF、损坏 ELF、工具缺失测试；
- 对应使用文档和结果样例。

#### Phase 1C：V1 基础能力迁移

计划交付：

- Symbols、Strings 和 Security 基础 Analyzer；
- URL、Secret、Base64、JNI 等检测能力；
- 基础安全 Rule；
- `default`、`security` Profile；
- timeout、quiet、fail-fast 等参数行为补齐。

Phase 1 完整验收标准：

- 每个基础分析器可独立运行；
- `scan` 可组合基础分析器；
- 单模块失败不影响无依赖模块；
- Text 和 JSON 输出可用；
- 文档中声明为可用的 CLI 参数均实际生效；
- V1 在迁移期间保持可用。

### Phase 2：统一结果、Finding 与缓存

交付：

- `AnalysisResult` 和 `Finding` Schema；
- Artifact Store；
- 缓存复用和失效；
- Markdown、HTML 报告；
- Profile 和配置系统。

验收标准：

- JSON 通过 Schema 校验；
- 同一输入重复执行可命中缓存；
- 可从已有 JSON 生成报告；
- 报告包含模块状态、版本和诊断信息。

### Phase 3：ELF 深度分析

交付：

- Section、Segment、Dynamic、Relocation、TLS 和 Version；
- 完整导入/导出符号；
- DWARF；
- C++ RTTI 和 vtable 基础恢复。

### Phase 4：代码与图分析

交付：

- 反汇编和函数边界；
- CFG；
- Call Graph；
- 基础 Data Flow；
- GraphML/GEXF 导出。

### Phase 5：安全与识别

交付：

- 安全保护检测；
- 危险 API 调用点和规则；
- 敏感数据规则；
- 算法、第三方库和编译器识别；
- Finding 去重和风险模型。

### Phase 6：Binary Diff

交付：

- ELF、符号、函数、CFG 和 Finding 差异；
- 版本变化摘要；
- Patch 辅助分析。

### Phase 7：高级可选工具

交付：

- AI 辅助解释和命名；
- 隔离动态分析；
- Fuzz Target 和 Harness 辅助；
- Crash 聚类和复现信息。

Web UI、REST API、服务端数据库和企业级平台能力列入 Future Work，不作为 V2 CLI 完成条件。

## 22. 推荐技术方向

| 能力 | V2 优先方向 | 说明 |
|---|---|---|
| CLI | `argparse` 或 Typer | 首期可复用现有 `argparse`，必要时再迁移 |
| ELF | LIEF、pyelftools 或外部 binutils | 选择一个主解析路径，外部工具作为补充或回退 |
| DWARF | pyelftools、libdwarf 或 LLVM DWARF | 按性能和覆盖范围评估 |
| 反汇编 | Capstone 或 LLVM MC | 重点验证 ARM/AArch64 |
| 图分析 | 内部图模型 + NetworkX | 不强制依赖 Neo4j |
| 动态分析 | Frida、QBDI 等 | 必须按 Linux/Android 环境隔离 |
| AI | Provider Adapter | 支持关闭、离线或远程提供方 |
| 存储 | JSON 文件 + 可选 SQLite 索引 | 保持本地优先和可迁移性 |
| 报告 | JSON Schema + 模板渲染 | Renderer 与 Analyzer 分离 |

具体组件必须经过以下评估后才能确定：

- 架构和平台支持；
- License；
- API 稳定性；
- 性能；
- 错误隔离；
- 安装和分发成本。

## 23. 配套文档

当前仓库已补充以下文档：

```text
docs/
├── README.md                    文档导航
├── getting-started.md           安装和快速开始
├── user-guide.md                V2 使用手册
├── cli-reference.md             当前 CLI 参数和退出码
├── architecture.md              分层架构和运行链路
├── extension-development.md     Analyzer/Rule/Profile/Renderer 开发
├── migration-v1-to-v2.md        V1 到 V2 迁移策略
└── project-status.md            当前状态和路线图
```

后续还需随着对应功能实现补充：

```text
docs/
├── result-finding-schema.md
├── cache-artifact-store.md
├── elf-symbol-dwarf.md
├── disassembler-cfg-callgraph.md
├── security-rules-risk-model.md
├── binary-diff.md
├── dynamic-sandbox.md
├── ai-provider.md
├── fuzz.md
├── report-formats.md
├── testing-fixtures.md
└── adr/
```

文档必须明确区分“当前实现”“框架接口”和“未来规划”，避免将占位命令描述为已完成能力。

## 24. 待决策事项

以下事项在进入对应阶段前需要形成 ADR（Architecture Decision Record）：

1. CLI 继续使用 `argparse` 还是迁移到 Typer；
2. ELF 主解析器采用 Python 库、LIEF 还是外部 binutils；
3. 插件发现使用 Python Entry Point 还是显式插件目录；
4. Result/Finding Schema 的版本策略；
5. 本地缓存是否需要 SQLite 索引；
6. 反汇编和函数边界识别的主要实现；
7. AI Provider 接口和默认数据出域策略；
8. 动态分析的 Linux/Android 隔离环境。

## 25. 当前实现基线

截至 2026-08-04，V2 的工程基线如下：

| 模块 | 状态 |
|---|---|
| CLI 命令树 | 已实现 |
| 单文件 TargetResolver | 已实现 |
| Analyzer/Rule/Profile/Renderer SDK | 已实现 |
| 依赖 DAG 和循环检测 | 已实现 |
| Scheduler | 串行已实现，并发未实现 |
| Text/JSON 输出 | 已实现 |
| 具体内置 Analyzer | 未实现 |
| 内置 Rule/Profile | 未实现 |
| Runtime Cache | 未实现 |
| 外部插件发现 | 未实现 |
| Markdown/HTML/SARIF | 未实现 |
| 高级分析命令 | 仅占位 |

当前运行无 Analyzer 的 `scan` 会成功返回目标元数据和 `NO_ANALYZERS_SELECTED` warning；运行 `file`、`elf` 等单项命令会因 Analyzer 尚未注册返回结构化规划错误。该行为用于验证外部框架，不代表 V2 已具备实际 ELF 扫描能力。

---

本文档定义 SOInsight V2 的 CLI 工具箱总体方向。各模块的算法、数据结构、命令参数和验收样例应在后续模块设计文档中进一步细化。
