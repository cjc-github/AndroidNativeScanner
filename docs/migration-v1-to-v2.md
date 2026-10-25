# SOInsight V1 到 V2 迁移指南

## 1. 迁移目标

迁移不是把 V1 类原样搬入新目录，而是将能力放入六大产品域，并适配统一 Target、Result、Finding、DAG 和 CLI。

V1 在 V2 达到真实能力验收前继续可用。

## 2. 领域映射

| V1 能力 | V2 产品能力 | 推荐实现 | 状态 |
|---|---|---|---|
| 文件属性/哈希 | `basic.file` | Analyzer | 已迁移 |
| ELF Header | `basic.elf` | Analyzer | 已迁移 |
| 导入导出/JNI 符号 | `basic.symbols` | Analyzer + 可选 Rule | 已迁移 |
| 字符串提取 | `advanced.strings` | Analyzer | 待迁移 |
| URL/Base64/敏感字符串 | `advanced.strings` 事实 + `security.*` Rule | Analyzer + Rule | 待迁移 |
| 危险函数 | `security.dangerous-api` | Analyzer，依赖 `basic.symbols` | 已迁移 |
| 基础风险汇总 | `security.risk` | 聚合 Analyzer/Rule | 待迁移 |
| 目录批量扫描 | `automation.workflow` | Workflow/批处理编排 | 待迁移 |
| 文本报告 | `automation.report` + Renderer | 报告编排与展示分离 | 待迁移 |
| 调试信息/参数名 | `basic.dwarf` | Analyzer，依赖 `basic.elf` | 已迁移 |

`basic.symbols` 相比 V1 `SymbolAnalyzer` 的差异：V1 只做 `nm -D` 导出名列举加 RCE 关键词匹配；V2 直接解析符号表（不依赖外部 binutils），并把 V1 的 URL/Secret/Base64/JNI 关键词思路留给后续 `security.*` Rule，事实层只保留可证明的符号与签名信息。

`security.dangerous-api` 相比 V1 的 RCE 关键词匹配：V1 是子串匹配，会把 `memcpy`、`printf` 这类常见原语全部报出；V2 按符号名精确匹配一张数据化规则表，FORTIFY 变体与前导下划线先归一化，导入/导出分开记录，且明确区分“能力可达”与“已被调用”。

## 3. 迁移步骤

1. 明确能力归属和稳定 ID；
2. 把 V1 命令调用封装到 `ToolRunner`；
3. 将解析结果转换为 `AnalysisResult.data`；
4. 将风险判断从采集逻辑拆到 Rule；
5. 声明 namespaced 依赖；
6. 在 `register_builtin_analyzers()` 注册；
7. 为领域命令、`scan --module` 和 JSON 输出补测试；
8. 使用同一样本对比 V1/V2；
9. 更新模块状态和字段文档。

## 4. 推荐顺序

### 第一纵向链路

```text
basic.file
  → basic.elf
  → security.hardening
  → Finding
  → JSON Renderer
```

它验证基础分析、安全分析和统一输出的跨域闭环。

### 第一条符号链路（✅ 已完成）

```text
basic.file
  → basic.elf
  → basic.symbols
  → 签名清单
  → Text/JSON/Markdown/HTML Renderer
```

### 调试信息链路（✅ 已完成）

```text
basic.file
  → basic.elf
  → basic.dwarf
  → 参数名/参数类型/返回类型/声明位置
  → 渲染层与 basic.symbols 联合
```

### 第二批：迁移 V1 事实

```text
basic.symbols        （✅ 已迁移）
basic.dwarf          （✅ 已迁移）
security.dangerous-api（✅ 已迁移）
advanced.strings
security.risk
```

### 第三批：加深基础分析

```text
basic.types / basic.cpp
basic.disasm → basic.cfg/basic.callgraph/basic.dataflow
```

### 后续能力域

- 高级分析：算法、协议、第三方库、编译器、混淆；
- 动态分析：先完成沙箱和授权，再实现 trace/coverage；
- AI 分析：在稳定事实和 Finding 之后接入；
- 自动化：基于稳定结果实现 Diff、Fuzz、报告和 CI Gate。

## 5. 数据与兼容策略

- 旧 CLI 入口 `python3 main.py` 保持不变；
- V2 canonical CLI 使用领域命令；
- 隐藏扁平别名仅作为开发期兼容，不承诺长期稳定；
- V2 结果必须包含 schema、工具和 Analyzer 版本；
- 字段变更通过 Schema 版本管理，不依赖终端文本兼容；
- V1/V2 并行期应建立 Golden 样本对照。

## 6. 完成定义

单项迁移完成需同时满足以下 10 项：

1. 产品能力归属和 ID 明确；
2. 真实 Analyzer 已注册；
3. 输入/输出字段文档化；
4. 依赖进入 DAG；
5. 错误和超时结构化；
6. 风险判断与事实采集合理分离；
7. 领域命令和组合扫描可用；
8. Text/JSON 测试通过；
9. V1 对照结果可解释；
10. 文档与项目状态更新。

### 已迁移能力核对（2026-10-25）

| 能力 | 完成定义 | 说明 |
|---|---|---|
| `basic.file` | 已满足 | 文件属性、SHA-256、Magic 与格式识别；内置 Profile `quick` 成员 |
| `basic.elf` | 已满足 | 纯 Python ELF 头/PHDR/段表，不依赖 binutils |
| `basic.symbols` | 已满足 | demangler 与参考实现全量比对 0 差异，pyelftools 审计 0 遗漏 0 多报（第 9 项以独立基准满足，强于 V1 对照） |
| `basic.dwarf` | 已满足 | 依赖 `basic.elf`，渲染层与 `basic.symbols` 联合 |
| `security.hardening` | 已满足 | 基于 ELF/PHDR 事实生成 PIE/NX/RELRO Finding；第一条跨域链路终点 |
| `security.dangerous-api` | 已满足 | 依赖 `basic.symbols`，精确匹配 + FORTIFY 归一化；V1 子串匹配的结构化替代 |

尚未迁移的能力（`advanced.strings`、`security.risk`、URL/Secret/Base64/JNI 规则等）以上述 10 项作为验收清单，迁移完成时在表中补行。
