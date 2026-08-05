# SOInsight V1 到 V2 迁移指南

## 1. 迁移目标

迁移不是把 V1 类原样搬入新目录，而是将能力放入六大产品域，并适配统一 Target、Result、Finding、DAG 和 CLI。

V1 在 V2 达到真实能力验收前继续可用。

## 2. 领域映射

| V1 能力 | V2 产品能力 | 推荐实现 |
|---|---|---|
| 文件属性/哈希 | `basic.file` | Analyzer |
| ELF Header | `basic.elf` | Analyzer |
| 导入导出/JNI 符号 | `basic.symbols` | Analyzer + 可选 Rule |
| 字符串提取 | `advanced.strings` | Analyzer |
| URL/Base64/敏感字符串 | `advanced.strings` 事实 + `security.*` Rule | Analyzer + Rule |
| 危险函数 | `security.dangerous-api` | Analyzer/Rule，依赖 symbols/callgraph |
| 基础风险汇总 | `security.risk` | 聚合 Analyzer/Rule |
| 目录批量扫描 | `automation.workflow` | Workflow/批处理编排 |
| 文本报告 | `automation.report` + Renderer | 报告编排与展示分离 |

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

### 第二批：迁移 V1 事实

```text
basic.symbols
advanced.strings
security.dangerous-api
security.risk
```

### 第三批：加深基础分析

```text
basic.dwarf → basic.types/basic.cpp
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

单项迁移完成需同时满足：

- [ ] 产品能力归属和 ID 明确；
- [ ] 真实 Analyzer 已注册；
- [ ] 输入/输出字段文档化；
- [ ] 依赖进入 DAG；
- [ ] 错误和超时结构化；
- [ ] 风险判断与事实采集合理分离；
- [ ] 领域命令和组合扫描可用；
- [ ] Text/JSON 测试通过；
- [ ] V1 对照结果可解释；
- [ ] 文档与项目状态更新。
