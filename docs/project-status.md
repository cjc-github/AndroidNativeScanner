# SOInsight V2 项目状态与路线图

**状态日期：2026-08-10**

## 1. 当前里程碑

> Phase 1A++ — 六大产品模块、共享技术框架、CLI 输出规范、`basic.file`/`basic.elf` 真实 Analyzer、第一条跨域链路（`basic.file → basic.elf → security.hardening`）和内置 Profile 已完成；运行时基础设施仍在建设中。

这里的”模块完成”指模块目录、能力 ID、CLI 路由和测试完成；`basic.file` 是首个接入的真实 Analyzer，不代表 42 项业务能力已经实现。

## 2. 已完成

### 产品外部框架

- [x] 六个一级产品模块：基础、高级、安全、动态、AI、自动化；
- [x] 原始设计 40 项能力进入模块目录；
- [x] 补充报告自动化和工作流自动化；
- [x] `<module>.<capability>` 命名空间；
- [x] 领域 CLI 命令树；
- [x] `modules list/show`；
- [x] `scan --module` 跨域展开；
- [x] 隐藏开发期兼容别名。

### 技术框架

- [x] 独立 `src/soinsight/` 包和 console script；
- [x] Target/Result/Finding/Diagnostic；
- [x] Analyzer/Rule/Profile/Renderer SDK 和 Registry；
- [x] 依赖 DAG、循环检测和串行 Scheduler；
- [x] 异常隔离、依赖跳过和结果聚合；
- [x] Text/JSON Renderer；
- [x] ToolRunner、ArtifactStore 和 PluginLoader 边界；
- [x] Wheel 构建脚本和入口校验；
- [x] 内置 `basic.file` Analyzer（文件属性、SHA-256、Magic 与格式识别）；
- [x] 内置 `basic.elf` Analyzer（ELF 类、字节序、类型、机器、入口与段表计数）；
- [x] 内置 `security.hardening` Analyzer（基于 ELF 事实生成 Finding）；
- [x] 第一条真实跨域链路：`basic.file → basic.elf → security.hardening`；
- [x] 内置 `quick`（`basic.file`/`basic.elf`）和 `security`（`security.hardening`）Profile；
- [x] Runtime 文件缓存（按目标 sha256 + analyzer 版本命中/写入）；
- [x] DAG stage 并发执行（`jobs > 1` 时同 stage Analyzer 并行）；
- [x] Python entry point 插件发现（组 `soinsight.analyzers`）；
- [x] Markdown、HTML 报告渲染器；
- [x] CLI 输出规范 P0/P1/P2：状态列、分组 help、doctor、quiet、TTY 颜色、窄终端布局和 JSON schema 文档。

### 测试

- [x] DAG 排序与循环检测；
- [x] Runtime 顺序、失败隔离和依赖跳过；
- [x] RuleEngine；
- [x] CLI JSON、缺失 Analyzer 和 Profile；
- [x] 六大模块顺序、能力查找和命名空间校验；
- [x] `modules list --format json`；
- [x] `scan --module` 展开；
- [x] YAML Schema、托管/外部配置、活动配置；
- [x] `config create/list/show/validate/use/current/clear/set/unset`；
- [x] YAML 模块/功能点选择、排除、Runtime/输出/能力参数合并。

当前自动化测试：`61 passed`。

## 3. 已有外壳但未实现

| 范围 | 已有部分 | 缺少部分 |
|---|---|---|
| 六大模块 | Catalog、CLI、ID | `basic.file`/`basic.elf`/`security.hardening` 之外的 Analyzer/Rule/Provider |
| `scan` | 目标解析、CLI/YAML 选择、Runtime、输出、`basic.file`、内置 Profile（`quick`/`security`） | 无 |
| Binary Diff | 双目标命令形态 | 多目标 Request 与 Diff 引擎 |
| Dynamic | 命令和能力定义 | 授权、沙箱、采集器 |
| AI | 命令和能力定义 | Provider、隐私、证据引用、成本治理 |
| Automation | 能力目录 | Workflow/CI/Fuzz 编排器 |
| Cache | 配置、FileArtifactStore、Runtime 命中/写入 | 失效/清理 |
| Plugins | Registry/Loader 边界、entry point 自动发现 | 兼容协议 |
| Reports | Text/JSON、Markdown、HTML | Schema、SARIF |
| Parallel | DAG stage、`jobs>1` stage 内并发 | 资源预算 |

## 4. 里程碑：第一条真实跨域链路（✅ 已完成）

目标：

```text
basic.file → basic.elf → security.hardening → Finding → JSON
```

任务：

1. 实现并注册 `basic.file`（✅ 已完成）；
2. 实现并注册 `basic.elf`（✅ 已完成）；
3. 实现 `security.hardening` 和基础规则（✅ hardening 已完成；基础规则待做）；
4. 固化数据字段与依赖（待做）；
5. 增加 `quick`/`security` Profile（✅ 已完成）；
6. 增加非 ELF、损坏 ELF、工具缺失测试（待做）；
7. 与 V1 样本结果对照（待做）。

验收：

```bash
soinsight basic file libfoo.so
soinsight basic elf libfoo.so
soinsight security hardening libfoo.so
soinsight scan libfoo.so --module basic,security --format json
```

相关命令已输出真实结果，不再依赖测试注入。

## 5. 后续 Roadmap

### Phase 1B：V1 能力迁移

- `basic.symbols`；
- `advanced.strings`；
- `security.dangerous-api`；
- `security.risk`；
- V1 URL/Secret/Base64/JNI 规则迁移。

### Phase 2：共享基础设施

- JSON Schema 和兼容测试；
- 内置 Profile（✅ 已完成）；
- Runtime 缓存（✅ 已完成）；
- Markdown/HTML（✅ 已完成）与 SARIF；
- 插件发现（✅ 已完成）；
- 并发（✅ 已完成）与资源预算。

### Phase 3：基础与高级分析深化

- DWARF、类型、C++；
- 反汇编、CFG、Call Graph、Data Flow；
- 算法、协议、格式、库、编译器和混淆识别。

### Phase 4：安全分析闭环

- 漏洞模式；
- 证据链、去重、置信度和风险评分；
- CI Gate 和基线抑制。

### Phase 5：动态分析

- 明确授权和隔离执行器；
- Trace、参数、内存、系统调用和覆盖率；
- 静态/动态结果关联。

### Phase 6：AI 分析

- Provider 抽象和本地优先策略；
- 命名、类型/结构恢复辅助；
- 算法/协议/漏洞/汇编解释；
- 证据引用、模型版本和可复现性。

### Phase 7：自动化

- Binary Diff；
- Fuzz Target/Harness/Seed；
- Crash 聚类；
- 报告流水线、批处理、CI Gate 和 Workflow。

## 6. 当前不可宣称

在实现和验收前，不应宣称：

- V2 已具备 42 项真实分析能力；
- V2 已替代 V1；
- 动态分析会安全执行目标；
- AI 输出具备事实保证；
- 报告已支持 SARIF 或完整 Schema。

## 7. 发布门槛

公开测试版本至少需要：

- 第一条跨域真实链路（✅ 已完成）；
- File/ELF/Symbols/Strings/Hardening/Dangerous API；
- 内置 Profile（✅ 已完成）；
- CLI 与文档一致；
- JSON Schema；
- V1/V2 Golden 回归；
- License；
- 安装、升级、卸载和安全说明。
