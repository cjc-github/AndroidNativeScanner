# SOInsight V2 模块体系

## 1. 模块定义

SOInsight V2 以 `design/design_v2.0.md` 为唯一主设计基线。一级模块固定为六个能力域：

| 模块 ID | 中文名 | 能力数 | CLI 前缀 | 定位 |
|---|---|---:|---|---|
| `basic` | 基础分析 | 10 | `soinsight basic` | 建立二进制、ELF、代码结构和统一 IR 基础事实 |
| `advanced` | 高级分析 | 8 | `soinsight advanced` | 从基础事实识别字符串、算法、协议、工具链等语义 |
| `security` | 安全分析 | 4 | `soinsight security` | 形成安全 Finding、证据和风险结论 |
| `dynamic` | 动态分析 | 5 | `soinsight dynamic` | 在授权与隔离环境中采集运行时证据 |
| `ai` | AI 分析 | 8 | `soinsight ai` | 消费已有证据进行语义恢复与解释 |
| `automation` | 自动化 | 7 | `soinsight automation` | 组合能力形成 Diff、Fuzz、报告和 CI 工作流 |

前 40 项能力来自 V2 原始设计；`automation.report` 和 `automation.workflow` 是为了兑现“自动化报告、批处理和 CI 集成”目标而补充的编排能力。

## 2. 能力目录

### 2.1 基础分析

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `basic file` | `basic.file` | 文件分析 |
| `basic elf` | `basic.elf` | ELF 解析 |
| `basic symbols` | `basic.symbols` | Symbol 解析 |
| `basic dwarf` | `basic.dwarf` | DWARF 解析 |
| `basic types` | `basic.types` | 类型恢复 |
| `basic cpp` | `basic.cpp` | C++ 恢复 |
| `basic disasm` | `basic.disasm` | 反汇编 |
| `basic cfg` | `basic.cfg` | CFG 恢复 |
| `basic callgraph` | `basic.callgraph` | Call Graph 恢复 |
| `basic dataflow` | `basic.dataflow` | Data Flow 分析 |

### 2.2 高级分析

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `advanced strings` | `advanced.strings` | 字符串分析 |
| `advanced constants` | `advanced.constants` | 常量分析 |
| `advanced algorithm` | `advanced.algorithm` | 算法识别 |
| `advanced protocol` | `advanced.protocol` | 协议识别 |
| `advanced file-format` | `advanced.file-format` | 文件格式识别 |
| `advanced library` | `advanced.library` | 第三方库识别 |
| `advanced compiler` | `advanced.compiler` | 编译器识别 |
| `advanced obfuscation` | `advanced.obfuscation` | 混淆识别 |

### 2.3 安全分析

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `security hardening` | `security.hardening` | 安全保护检测 |
| `security dangerous-api` | `security.dangerous-api` | 危险 API 检测 |
| `security vulnerability` | `security.vulnerability` | 漏洞模式识别 |
| `security risk` | `security.risk` | 风险评分/评估 |

### 2.4 动态分析

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `dynamic trace` | `dynamic.trace` | Runtime Trace |
| `dynamic arguments` | `dynamic.arguments` | 参数采集 |
| `dynamic memory` | `dynamic.memory` | 内存分析 |
| `dynamic syscalls` | `dynamic.syscalls` | 系统调用分析 |
| `dynamic coverage` | `dynamic.coverage` | 覆盖率分析 |

### 2.5 AI 分析

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `ai function-name` | `ai.function-name` | 函数命名 |
| `ai parameter-semantics` | `ai.parameter-semantics` | 参数语义恢复 |
| `ai struct-recovery` | `ai.struct-recovery` | 结构体恢复 |
| `ai module-identification` | `ai.module-identification` | 模块识别 |
| `ai algorithm-explanation` | `ai.algorithm-explanation` | 算法解释 |
| `ai protocol-explanation` | `ai.protocol-explanation` | 协议解释 |
| `ai vulnerability-explanation` | `ai.vulnerability-explanation` | 漏洞解释 |
| `ai assembly-explanation` | `ai.assembly-explanation` | 汇编自然语言解释 |

### 2.6 自动化

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `automation binary-diff OLD NEW` | `automation.binary-diff` | Binary Diff |
| `automation fuzz-target TARGET` | `automation.fuzz-target` | Fuzz Target 识别 |
| `automation harness TARGET` | `automation.harness` | Harness 生成 |
| `automation seed TARGET` | `automation.seed` | Seed 生成 |
| `automation crash-cluster TARGET` | `automation.crash-cluster` | Crash 聚类 |
| `automation report TARGET` | `automation.report` | 报告自动化 |
| `automation workflow TARGET` | `automation.workflow` | 批处理、Profile、CI Gate 和工作流编排 |

## 3. 产品模块与技术扩展点

两套视图正交存在：

```text
产品视图（用户看到）
基础分析 / 高级分析 / 安全分析 / 动态分析 / AI 分析 / 自动化

技术视图（开发者实现）
CLI / Application / Analyzer / Rule / Planner / Scheduler /
Result Model / Renderer / Artifact Store / Plugin Loader / Tool Runner
```

一个产品能力通常由一个或多个 Analyzer、Rule、外部工具适配器和 Renderer 协作完成。例如“危险 API 检测”属于安全分析，不因为它内部使用 Symbol Analyzer、Call Graph Analyzer 和 Rule Engine 就被拆成多个产品模块。

## 4. 跨域依赖规则

允许跨域依赖，但必须通过稳定能力 ID、DAG 和标准化结果完成：

```text
security.dangerous-api
  requires: basic.symbols, basic.disasm, basic.callgraph

ai.vulnerability-explanation
  consumes: security.vulnerability / security.risk findings

automation.harness
  consumes: basic.types, advanced.protocol, dynamic.coverage
```

约束：

1. Analyzer 通过 `requires` 声明依赖；
2. Planner 补全依赖并检查循环；
3. 下游从 `AnalysisContext` 读取统一结果；
4. 禁止一个模块直接 import 并调用另一个模块 Analyzer 的 `analyze()`；
5. AI 能力优先解释已有证据，不重复执行安全或基础分析；
6. 自动化能力负责组合，不复制底层分析逻辑。

## 5. 当前实现状态

已实现：

- 六大模块注册目录 `src/soinsight/modules/`；
- 42 项能力定义及命名空间校验；
- 领域命令树；
- `modules list/show`；
- `scan --module basic,security` 对单目标兼容能力进行展开；
- 单目标能力到 Runtime 的路由；
- 开发期旧扁平命令隐藏兼容别名。

未实现：

- 42 项能力对应的具体 Analyzer/Rule/Provider；
- 双目标及复杂输入能力的统一 Request 模型；
- 动态分析隔离执行器；
- AI Provider、隐私策略和成本控制；
- 自动化工作流执行引擎。

因此“模块已搭建”表示产品目录、CLI 外壳和技术接入点已建立，不表示业务分析结果已经可用。

## 6. YAML 中的模块与能力引用

YAML 的 `analysis.modules` 使用模块 ID 和模块内 command，例如 `basic: [file, elf]`；`analysis.capabilities`、`analysis.exclude` 和 `capability_options` 使用完整 ID，例如 `security.hardening`。这样既保持用户侧六大模块结构，也保持 Runtime 的稳定 namespaced 能力标识。详见 [YAML 配置指南](configuration.md)。
