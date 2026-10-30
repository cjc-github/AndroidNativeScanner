# 未完成分析能力与技术债

**快照日期：2026-10-28**（与 `feature-status.md`、`project-status.md` 同口径核实）

本文档对六大模块中**只有外壳或尚未落地**的能力做逐项分析：每项记录"现状 / 需要什么 / 建议的事实形态 / 依赖"，并在文末给出实现顺序建议。已实现的 27/45 项能力见 `feature-status.md` §一，能力定义见 `module-system.md`，阶段路线见 `project-status.md`。

统计：`basic` 0/12、`advanced` 0/8、`security` 0/5、`dynamic` 4/5、`ai` 8/8、`automation` 6/7 —— 共 **18/45** 项外壳能力（`dynamic.trace` 已接入，默认拒绝执行，见 §4；`automation.fuzz-target` 已按静态版落地，见 §6）。调用它们返回 `ANALYSIS_PLAN_ERROR`（退出码 3），这是当前框架阶段的预期行为。

---

## 1. 基础分析（basic，0 项外壳）

`basic` 十二项能力全部已实现：`basic.file`/`basic.elf`/`basic.symbols`/`basic.dwarf`/`basic.types`/`basic.cpp`/`basic.disasm`/`basic.cfg`/`basic.callgraph`/`basic.dataflow`/`basic.dynamic`/`basic.xref`。反汇编族（disasm → cfg → callgraph → dataflow/xref）与动态链接事实已补齐，`security.dangerous-api`/`security.vulnerability` 的调用点证据接入见 §3。

---

## 2. 高级分析（advanced，6 项外壳）

`advanced` 八项能力全部已实现：`advanced.strings`/`advanced.constants`/`advanced.algorithm`/`advanced.file-format`/`advanced.library`/`advanced.compiler`/`advanced.protocol`/`advanced.obfuscation`。全部是纯 Python 的链接级与字节级事实提取，不依赖外部工具链。

各能力的证据形态与边界：`advanced.file-format` 报告外层与内嵌格式的偏移和结构校验结果；`advanced.library` 与 `advanced.protocol` 用 `DT_NEEDED`/符号/字符串交叉，单源标 `single`、多源标 `corroborated`；`advanced.compiler` 从 `.comment` 与 note 段取横幅并抽版本；`advanced.obfuscation` 报告壳签名与高熵分节。

剩余演进点（不是外壳欠账）：

- **协议语义级识别**：当前只做链接级特征，报文结构与状态机识别需要动态证据；
- **控制流平坦化判定**：需要比较 `basic.cfg` 恢复出的图形态，留待后续能力；
- **库版本精确匹配**：版本串只能给出线索，无法从链接层证明具体补丁版本。

---

## 3. 安全分析（security，0 项外壳）

四项能力均已实现（`hardening`/`dangerous-api`/`vulnerability`/`risk`），无外壳欠账。剩余演进点：

- **调用点证据**（✅ 已完成）：`basic.callgraph` 已作为 `security.dangerous-api` 的软依赖接入，导入型命中带调用点数量与地址，证据标 `call-site`，并随 `security.vulnerability` 的证据链传递；无调用图时保持 `linkage`。剩余演进点是**参数可控性**：证明调用点参数来自外部输入需要污点分析或动态观测，`basic.dataflow` 目前只做函数内 use-def，不足以支撑该结论。
- **软依赖（order-only dependency）**（✅ 已完成，见 §7 D1）：调度器已支持 `optional_requires`。`security.risk` 仍然保持硬依赖并在非 ELF 目标上整体跳过——空集上的风险分没有解释力，「缺上游就不给分数」比「给 0 分」更诚实；这是有意的设计选择，不是待办。

---

## 4. 动态分析（dynamic，1 项已接入 / 4 项外壳）

动态族的共同前置 —— **授权门 + 隔离执行器（D9）** —— 已经落地，形式是
`infrastructure/execution.py`：

- **授权默认拒绝**：配置里没有 `dynamic_execution.authorized: true` 就什么都不跑；可选的
  `allow_targets` 白名单按真实路径比对。拒绝不是崩溃，而是一条
  `DYNAMIC_EXECUTION_NOT_AUTHORIZED` 警告加 `state: not-authorized` 的事实。
- **隔离靠探测，不靠假设**：`detect_sandbox()` 依次探测 `bwrap` > `firejail` > `docker` >
  `unshare` 并给出包裹命令；**没有裸执行的兜底**——探测不到就报
  `DYNAMIC_SANDBOX_UNAVAILABLE` 并拒绝。
- **计划与执行分离**：`DryRunExecutor` 只产出沙箱命令行（含超时与内存上限），
  `SubprocessSandboxExecutor` 必须同时满足「已授权」与「构造时 `allow_execution=True`」
  两个条件才会真正启动进程；当前没有任何内置 Analyzer 打开它。

`dynamic.trace` 已接入调度，走完授权 → 沙箱 → 计划的完整判定链，三种状态分别是
`not-authorized` / `no-sandbox` / `planned`（`planned` 时给出待执行的 argv，但
`executed: false`）。**它不采集事件**：采集器与 `dlopen` 驱动（harness）属于下一步。

| 能力 | 现状 | 还缺什么 |
|---|---|---|
| `dynamic.trace` | 已接入：授权门 + 沙箱探测 + dry-run 计划 | 采集器（ptrace/frida 或 eBPF）、harness、事件流进统一结果模型 |
| `dynamic.arguments` | 外壳 | 同上 + 采样点选择（结合 `basic.callgraph`） |
| `dynamic.memory` | 外壳 | `/proc/<pid>/maps` 级别的观测点白名单 |
| `dynamic.syscalls` | 外壳 | seccomp/ptrace 拦截策略 |
| `dynamic.coverage` | 外壳 | 与 `basic.cfg` 块号对齐 |

- **依赖**：采集器需要一个能加载 `.so` 的驱动进程，静态分析给不出来；
  `automation.harness` 与本节的 harness 需求是同一件事。
- **结果模型**：动态事实与静态 Finding 的关联（如"该危险 API 确实被调用且参数可控"）仍是
  Phase 5 的验收点。

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

## 6. 自动化（automation，1 项已实现 / 6 项外壳）

| 能力 | 现状与做法 | 依赖 |
|---|---|---|
| `automation.binary-diff` | 命令形态已建（`old new` 双目标），缺多目标 Request 模型与 Diff 引擎本体（函数集/CFG/Finding 差异） | 多目标 Request（§7 D8）、`basic.symbols`/`basic.types`、CFG |
| `automation.fuzz-target` | ✅ 静态版已落地：导出/JNI 入口排序、参数按形状归类（含缓冲区+长度对判定）、启发式评分并标 `heuristic`；不做数据流分析，也不执行目标 | `basic.symbols`、`basic.types` |
| `automation.harness` | 按设计消费 `basic.types`/`advanced.protocol`/`dynamic.coverage` 生成 Harness；先输出模板型 harness | `basic.types`、`advanced.protocol` |
| `automation.seed` | 按 `advanced.file-format`/`advanced.protocol`/`advanced.constants` 事实生成种子语料 | 高级分析三项 |
| `automation.crash-cluster` | 输入是崩溃语料（来自 fuzz），按栈帧/信号/根因线索聚类；fuzz 底座前无输入源 | `automation.fuzz-target` 链路 |
| `automation.report` | 结果转换/归档/发布编排，可复用现有 Renderer 五格式；是最容易起步的一项 | Renderer（已实现） |
| `automation.workflow` | 批处理/Profile/流水线编排引擎；CI Gate 与基线抑制已在 `scan` 以 `--fail-on`/`--baseline` 形式落地，缺的是多目标与阶段编排 | 多目标与编排引擎 |

---

## 7. 框架层技术债（外壳已建或机制不全）

| 编号 | 债项 | 现状 | 需要什么 |
|---|---|---|---|
| D1 | 软依赖（仅排序的可选依赖） | ✅ 已落地：`optional_requires` 参与排序但不拉入计划，缺席时消费方走 `context.optional()` 降级；缓存按参与的可选依赖集合分键 | （无遗留） |
| D2 | 缓存治理 | 命中/写入按“代码指纹 / 目标 sha256 / analyzer 版本”三层隔离，`cache info/clean/prune` 可用 | （无遗留：随代码变更自动失效，`prune` 清理旧版本条目） |
| D3 | 插件兼容协议 | entry point 发现已实现 | 与外部插件的兼容协议定义 |
| D4 | 报告 Schema | `docs/cli-output-schema.md` 只是文档 | 机器可校验 `.schema.json` + 兼容性测试 |
| D5 | 并行资源预算 | stage 内并发已实现 | 跨阶段总资源/内存预算 |
| D6 | 目录扫描 | V2 TargetResolver 只接受单文件 | 多目标 Request 模型（与 D8 同源） |
| D7 | doctor 分级 | 缺 binutils 报 info 而非 warning，并注明 binutils 仅 V1 legacy 管线需要、V2 Analyzer 均为纯 Python | （无遗留） |
| D8 | 多目标 Request 与 Diff 引擎 | 只有双目标命令形态 | 统一 Request 模型 + Diff 本体（支撑 binary-diff/目录扫描/批处理） |
| D9 | 动态执行底座 | ✅ 授权门（默认拒绝 + 白名单）、沙箱探测（bwrap/firejail/docker/unshare）、计划/执行分离与双重 opt-in 已落地 | 采集器与 harness（`dynamic.*` 余下部分） |
| D10 | AI Provider 抽象 | 无 | 本地优先策略、隐私防护、证据引用、模型版本与成本治理 |
| D11 | Automation 编排引擎 | 无 | Workflow、CI Gate、Fuzz 编排器、批处理流水线 |

---

## 8. 实现顺序建议

与 `project-status.md` 的 Phase 对齐（✅ = 已完成）：

```text
1. 软依赖 D1        —— 解锁聚合类 Analyzer 降级语义（Phase 4 前置）
2. 反汇编族         —— ✅ 底座决策、basic.disasm、basic.cfg、basic.callgraph
                       与 basic.dataflow 全部完成（Phase 3 主体）
3. advanced.family  —— ✅ 全部完成（algorithm/file-format/library/compiler 先行，
                       protocol 次之，obfuscation 收尾；Phase 3 收尾）
4. Phase 4 余项     —— 调用点证据接入 dangerous-api/vulnerability、CI Gate、基线抑制
5. 动态底座 D9      —— ✅ 授权门/沙箱/计划已落地；采集器与 harness 之后再接
                       dynamic.* 余下四项（Phase 5）
6. AI Provider D10  —— 先 ai.vulnerability-explanation（Finding 已就绪），
                       其余随证据丰富度推进（Phase 6）
7. automation       —— report/workflow 先行，fuzz 家族最后（Phase 7）
```

理由：`basic.cpp` 已完成（纯消费现有 facts，无新基础设施）；反汇编族已整体落地——`basic.disasm` 用 Capstone 作为可选依赖（缺失时降级为边界事实），`basic.cfg`/`basic.callgraph`/`basic.dataflow` 依次复用其指令、边界与 CFG 事实；`advanced.constants` 已给出算法常量证据，`advanced.algorithm` 是它的直接下游；advanced 余下五项（file-format/library/compiler/protocol/obfuscation）均已落地，全部复用 `infrastructure/elf` 的分节与符号事实；动态与 AI 都有共同底座，逐能力散做会重复付费。

---

## 9. 如何核验这份清单

```bash
# 能力目录与实现状态一目了然
PYTHONPATH=src python3 -m soinsight modules list
# 外壳行为（未实现能力返回 ANALYSIS_PLAN_ERROR，退出码 3）
PYTHONPATH=src python3 -m soinsight dynamic trace libfoo.so
# 已实现能力全量链路
PYTHONPATH=src python3 -m soinsight scan libfoo.so --module-available basic,security,advanced
```
