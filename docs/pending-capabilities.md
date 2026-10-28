# 未完成分析能力与技术债

**快照日期：2026-10-28**（与 `feature-status.md`、`project-status.md` 同口径核实）

本文档对六大模块中**只有外壳或尚未落地**的能力做逐项分析：每项记录"现状 / 需要什么 / 建议的事实形态 / 依赖"，并在文末给出实现顺序建议。已实现的 11/42 项能力见 `feature-status.md` §一，能力定义见 `module-system.md`，阶段路线见 `project-status.md`。

统计：`basic` 4/10、`advanced` 7/8、`security` 0/4、`dynamic` 5/5、`ai` 8/8、`automation` 7/7 —— 共 **31/42** 项外壳能力。调用它们返回 `ANALYSIS_PLAN_ERROR`（退出码 3），这是当前框架阶段的预期行为。

---

## 1. 基础分析（basic，4 项外壳）

### `basic.disasm`（反汇编：指令/函数边界/代码区域）

- **现状**：无反汇编层，这是 `cfg`/`callgraph`/`dataflow` 三项的共同前置。
- **需要什么**：指令解码器。需要先做依赖策略决策：引入 Capstone（Python 包依赖，符合"无外部工具依赖"原则但新增第三方依赖），还是自研最小解码器（x86-64/ARM/AArch64/ARM64 至少覆盖常用指令子集）。无论哪种，函数边界恢复都从已有事实出发：符号表给出已知函数地址区间，无符号区间用序言扫描（push rbp/mov rbp,sp、stp x29,x30 等）与对齐启发式补充。
- **建议事实形态**：`functions`（地址、长度、arch/mode）、`instructions`（分页/按函数聚合，不做全量数组）、`code_regions`（可执行段拆分）。
- **依赖**：`basic.elf`（Program Header 定位可执行段）+ `basic.symbols`（函数边界）。
- **风险**：反汇编是最大的新增基础设施，建议先支持 ELF 机器类型 `EM_AARCH64` 与 `EM_X86_64`（Android 两大主流架构）。

### `basic.cfg`（CFG：基本块/边/控制流结构）

- **现状**：无。依赖 `basic.disasm`。
- **需要什么**：在反汇编层之上做基本块划分（跳转/调用/返回指令切分），边恢复分两档：直接跳转可精确恢复；间接跳转（寄存器/内存目标）先用"未解析边"事实占位，不做猜测。
- **建议事实形态**：`basic_blocks`（按函数聚合，`start`/`end`/`successors`）、`edges`（`kind: branch/cond/indirect`）。
- **依赖**：`basic.file → basic.elf → basic.symbols → basic.disasm → basic.cfg`。

### `basic.callgraph`（Caller/Callee 与跨函数调用关系）

- **现状**：无。依赖 `basic.disasm`。
- **需要什么**：直接 `call` 目标解析（本地函数 + PLT/`JUMP_SLOT` 重定位映射到导入符号）；间接调用记 `indirect`，不猜测。与 `security.dangerous-api` 天然衔接——危险 API 的调用点证据依赖此能力（见 `security` 节）。
- **建议事实形态**：`call_edges`（caller/callee，`callee_kind: local/import/indirect`）、`callers_of`（反向索引）。
- **依赖**：`basic.disasm` + ELF 重定位事实（`infrastructure/elf` 已有 Section/Symbol，需补 `.rela.plt`/`.rela.dyn` 解析）。

### `basic.dataflow`（Use-Def/数据依赖/基础传播）

- **现状**：无。依赖 `basic.cfg`，是基础分析族中最重的一项。
- **需要什么**：按 ABI 建模寄存器/栈槽的 use-def；建议先做函数内（intra-procedural）分析，函数间传播推后。
- **建议事实形态**：`defs`/`uses`（按基本块聚合）、`reaches`（到达定义对，限量声明截断）。
- **依赖**：`basic.cfg`。风险与字符串联合（如"传入 `strcpy` 目标的是栈缓冲区"）属于 Phase 4 安全闭环的数据流证据，不在此能力内完成。

---

## 2. 高级分析（advanced，7 项外壳）

`advanced.strings` 已实现，以下 7 项多数可以复用它的提取与分节归属成果。

| 能力 | 现状与做法 | 依赖 |
|---|---|---|
| `advanced.constants` | 从 `.rodata`/`.data` 扫描已知特征常量表（AES S-box、MD5/CRC32 常量等）并给出偏移与分节归属；无需反汇编即可起步 | `basic.elf` + `advanced.strings` |
| `advanced.algorithm` | 常量签名（YARA 式字节模式）+ 导入符号名（OpenSSL/BoringSSL 系列）+ 导出算法名，交叉判定加密/哈希/压缩/编码 | `advanced.constants`、`basic.symbols` |
| `advanced.protocol` | 字符串线索（协议关键字、端口、消息头常量）+ 网络 import（`socket`/`connect` 等）做协议特征识别；语义级识别依赖动态/反汇编，先做链接级 | `advanced.strings`、`basic.symbols` |
| `advanced.file-format` | 数据段/文件内嵌 magic 扫描（ZIP/PNG/JPEG/Dex 等），报告偏移与外层归属 | `basic.file`、`advanced.strings` |
| `advanced.library` | `DT_NEEDED`/SONAME（需补 `infrastructure/elf` 的 dynamic 段解析）、版本字符串、符号命名空间指纹（`std::`、protobuf 等）识别第三方库与版本线索 | `basic.symbols` |
| `advanced.compiler` | `.comment`/build-id note/ABI tag note、工具链字符串、代码生成特征；note 解析在 `security.hardening`（GNU property）已有先例 | `basic.elf` |
| `advanced.obfuscation` | 高熵分节、UPX/壳签名、OLLVM 特征字符串可先做；控制流平坦化判定依赖 `basic.cfg`，放后 | `advanced.strings`、`basic.cfg` |

---

## 3. 安全分析（security，0 项外壳）

四项能力均已实现（`hardening`/`dangerous-api`/`vulnerability`/`risk`），无外壳欠账。剩余演进点：

- **调用点证据**：`security.dangerous-api` 与 `security.vulnerability` 目前基于链接级事实（符号名），证据不含调用上下文；`basic.callgraph`/`basic.dataflow` 实现后作为可选依赖接入，可提升证据等级与置信度（`module-system.md` §4 已预留此扩展）。
- **软依赖（order-only dependency）**：`security.risk` 在非 ELF 目标上随链整体跳过是有意行为；若要"缺上游按空集降级评分"，需要调度器支持仅排序的可选依赖（见 §7 技术债 D1）。

---

## 4. 动态分析（dynamic，5 项外壳）

动态族有共同的、比单个能力更大的前置：**授权门 + 隔离执行器**。没有这两层，任何采集器都不该落地。

| 能力 | 内容 | 共同前置之外需要什么 |
|---|---|---|
| `dynamic.trace` | 函数/模块/事件运行轨迹 | 采集器通道（ptrace/frida 或模拟器）；事件流进统一结果模型 |
| `dynamic.arguments` | 调用参数、返回值与上下文采集 | 同上 + 采样点选择（通常结合 `basic.callgraph`/hooks） |
| `dynamic.memory` | 内存映射、访问与关键数据观测 | 同上 + 观测点白名单（读 `/proc/<pid>/maps` 级别先做） |
| `dynamic.syscalls` | 系统调用与文件/网络/进程行为 | 同上 + seccomp/ptrace 拦截策略 |
| `dynamic.coverage` | 函数/基本块/边覆盖率 | 同上 + 与 `basic.cfg` 的块号对齐（覆盖率最终要对回静态 CFG） |

- **依赖**：全部依赖一个"动态执行底座"（授权声明、目标进程沙箱、采集器、结果回传），建议作为一个 Phase 5 里程碑一起验收，而不是逐能力散做。
- **结果模型**：动态事实与静态 Finding 的关联（如"该危险 API 确实被调用且参数可控"）是 Phase 5 的验收点之一。

---

## 5. AI 分析（ai，8 项外壳）

AI 族共同前置是 **Provider 抽象（本地优先策略）、隐私防护、证据引用与成本治理**。八项能力全部是"消费已有证据、输出解释"，不重复执行分析（`module-system.md` §4 规则 5）。

| 能力 | 消费的证据 | 备注 |
|---|---|---|
| `ai.function-name` | `basic.symbols` + `basic.types` + `advanced.strings` | 无符号函数依赖 `basic.disasm`/callgraph 特征 |
| `ai.parameter-semantics` | `basic.types` 签名/类型 | 依赖 `basic.disasm` 更佳 |
| `ai.struct-recovery` | `basic.types` 复合类型 | |
| `ai.module-identification` | `advanced.library` + 字符串 | |
| `ai.algorithm-explanation` | `advanced.algorithm` 证据 | |
| `ai.protocol-explanation` | `advanced.protocol` 证据 | |
| `ai.vulnerability-explanation` | `security.vulnerability`/`security.risk` Finding | **当前 Finding 已存在，可最先落地** |
| `ai.assembly-explanation` | `basic.disasm` 局部汇编 | 依赖反汇编层 |

---

## 6. 自动化（automation，7 项外壳）

| 能力 | 现状与做法 | 依赖 |
|---|---|---|
| `automation.binary-diff` | 命令形态已建（`old new` 双目标），缺多目标 Request 模型与 Diff 引擎本体（函数集/CFG/Finding 差异） | 多目标 Request（§7 D8）、`basic.symbols`/`basic.types`、CFG |
| `automation.fuzz-target` | 从导出符号与 JNI 入口识别可测试入口，从 `basic.types` 提取参数约束；先做静态版 | `basic.symbols`、`basic.types` |
| `automation.harness` | 按设计消费 `basic.types`/`advanced.protocol`/`dynamic.coverage` 生成 Harness；先输出模板型 harness | `basic.types`、`advanced.protocol` |
| `automation.seed` | 按 `advanced.file-format`/`advanced.protocol`/`advanced.constants` 事实生成种子语料 | 高级分析三项 |
| `automation.crash-cluster` | 输入是崩溃语料（来自 fuzz），按栈帧/信号/根因线索聚类；fuzz 底座前无输入源 | `automation.fuzz-target` 链路 |
| `automation.report` | 结果转换/归档/发布编排，可复用现有 Renderer 五格式；是最容易起步的一项 | Renderer（已实现） |
| `automation.workflow` | 批处理/Profile/CI Gate/流水线编排引擎；Phase 4 的 CI Gate 与基线抑制归此 | 多目标与编排引擎 |

---

## 7. 框架层技术债（外壳已建或机制不全）

| 编号 | 债项 | 现状 | 需要什么 |
|---|---|---|---|
| D1 | 软依赖（仅排序的可选依赖） | `requires` 既是排序依据也是跳过闸门 | 调度器新增 `order_only`/软依赖语义：上游缺席时降级为空集。规划与 `security.risk` 非 ELF 降级、`security.vulnerability` 聚合一起落地 |
| D2 | 缓存治理 | 命中/写入按“代码指纹 / 目标 sha256 / analyzer 版本”三层隔离，`cache info/clean/prune` 可用 | （无遗留：随代码变更自动失效，`prune` 清理旧版本条目） |
| D3 | 插件兼容协议 | entry point 发现已实现 | 与外部插件的兼容协议定义 |
| D4 | 报告 Schema | `docs/cli-output-schema.md` 只是文档 | 机器可校验 `.schema.json` + 兼容性测试 |
| D5 | 并行资源预算 | stage 内并发已实现 | 跨阶段总资源/内存预算 |
| D6 | 目录扫描 | V2 TargetResolver 只接受单文件 | 多目标 Request 模型（与 D8 同源） |
| D7 | doctor 分级 | 缺 binutils 报 info 而非 warning，并注明 binutils 仅 V1 legacy 管线需要、V2 Analyzer 均为纯 Python | （无遗留） |
| D8 | 多目标 Request 与 Diff 引擎 | 只有双目标命令形态 | 统一 Request 模型 + Diff 本体（支撑 binary-diff/目录扫描/批处理） |
| D9 | 动态执行底座 | 无 | 授权门、沙箱执行器、采集器（dynamic 五项共同前置） |
| D10 | AI Provider 抽象 | 无 | 本地优先策略、隐私防护、证据引用、模型版本与成本治理 |
| D11 | Automation 编排引擎 | 无 | Workflow、CI Gate、Fuzz 编排器、批处理流水线 |

---

## 8. 实现顺序建议

与 `project-status.md` 的 Phase 对齐（✅ = 已完成）：

```text
1. 软依赖 D1        —— 解锁聚合类 Analyzer 降级语义（Phase 4 前置）
2. 反汇编底座决策   —— Capstone vs 自研；然后 basic.disasm → basic.cfg
                       → basic.callgraph → basic.dataflow（Phase 3 主体）
3. advanced.family  —— constants/algorithm/file-format/library/compiler 先行，
                       protocol 次之，obfuscation 依赖 CFG 放最后（Phase 3 收尾）
4. Phase 4 余项     —— 调用点证据接入 dangerous-api/vulnerability、CI Gate、基线抑制
5. 动态底座 D9      —— 然后 dynamic.* 五项（Phase 5）
6. AI Provider D10  —— 先 ai.vulnerability-explanation（Finding 已就绪），
                       其余随证据丰富度推进（Phase 6）
7. automation       —— report/workflow 先行，fuzz 家族最后（Phase 7）
```

理由：`basic.cpp` 已完成（纯消费现有 facts，无新基础设施）；反汇编族是单点最大的基础设施投入，决策越早越好；动态与 AI 都有共同底座，逐能力散做会重复付费。

---

## 9. 如何核验这份清单

```bash
# 能力目录与实现状态一目了然
PYTHONPATH=src python3 -m soinsight modules list
# 外壳行为（未实现能力返回 ANALYSIS_PLAN_ERROR，退出码 3）
PYTHONPATH=src python3 -m soinsight basic callgraph libfoo.so
# 已实现能力全量链路
PYTHONPATH=src python3 -m soinsight scan libfoo.so --module-available basic,security,advanced
```
