# SOInsight V2 项目状态与路线图

**状态日期：2026-08-04**

## 1. 当前里程碑

当前处于：

> Phase 1A — V2 外部框架骨架完成，具体 Analyzer 迁移尚未开始。

## 2. 已完成

### 设计和工程化

- [x] V2 CLI 工具箱总体设计；
- [x] `src/soinsight/` 独立包；
- [x] Python 3.10+ 包配置；
- [x] `soinsight` console script；
- [x] V1/V2 入口隔离；
- [x] Wheel 构建验证。

### Core Runtime

- [x] Analyzer SDK 和 Registry；
- [x] AnalysisContext；
- [x] 依赖 DAG Planner；
- [x] 循环依赖检测；
- [x] 串行 Scheduler；
- [x] Analyzer 异常隔离；
- [x] 上游失败后的依赖跳过；
- [x] Rule SDK、Registry 和 RuleEngine；
- [x] Profile 模型和 Registry；
- [x] Result Aggregator。

### 模型和输出

- [x] `AnalysisTarget`；
- [x] `AnalysisResult`；
- [x] `ScanResult`；
- [x] `Finding`；
- [x] `Diagnostic`；
- [x] Text Renderer；
- [x] JSON Renderer；
- [x] Schema 版本字段。

### 基础设施边界

- [x] ConfigLoader 默认值和 CLI override；
- [x] ToolRunner；
- [x] ArtifactStore 接口；
- [x] FileArtifactStore 原子写入；
- [x] PluginLoader 占位接口；
- [x] 序列化工具。

### 测试

- [x] DAG 排序测试；
- [x] 循环依赖测试；
- [x] Runtime 执行顺序测试；
- [x] 失败隔离和依赖跳过测试；
- [x] RuleEngine 测试；
- [x] CLI JSON 集成测试；
- [x] 缺失 Analyzer 测试；
- [x] Profile 解析测试。

当前测试：`8 passed`。

## 3. 已有入口但未完成实际能力

| 能力 | 已有部分 | 缺少部分 |
|---|---|---|
| `scan` | CLI、目标解析、Runtime、输出 | 内置 Analyzer |
| `file/elf/...` | 命令和 Runtime 路由 | 对应具体 Analyzer |
| Profile | 模型和 Registry | 内置 Profile、配置加载 |
| Rule | SDK 和 Runtime 执行 | 内置安全规则和 CLI 管理 |
| Cache | 配置和 ArtifactStore | Runtime 命中、失效、清理 |
| Plugins | Registry 和 Loader 边界 | 外部发现和加载协议 |
| Parallel | DAG stage | 并发 Scheduler |
| Report | JSON 读取/格式化 | Schema 校验、HTML/Markdown/SARIF |
| Config | 默认值 | TOML/YAML/环境变量合并 |

## 4. 下一里程碑：Phase 1B

目标：完成第一个真实可用的最小分析链路。

推荐任务：

1. 实现并注册 `FileAnalyzer`；
2. 实现并注册 `ElfAnalyzer`；
3. 定义两个 Analyzer 的稳定数据字段；
4. 增加 `quick` Profile；
5. 增加非 ELF、损坏 ELF 和工具缺失测试；
6. 补充对应 CLI 示例和结果样例；
7. 验证 V1 不受影响。

验收标准：

```bash
soinsight file libfoo.so
soinsight elf libfoo.so
soinsight scan libfoo.so --profile quick --format json
```

三条命令均能输出真实分析结果，不再依赖测试注入 Analyzer。

## 5. 后续里程碑

### Phase 1C：迁移 V1 基础能力

- SymbolsAnalyzer；
- StringsAnalyzer；
- URL/Secret/Base64/JNI 检测器；
- 基础 Security Rules；
- default/security Profile。

### Phase 2：协议、报告和缓存

- JSON Schema 文件；
- Schema 兼容性测试；
- Artifact Store 接入 Runtime；
- 缓存键和失效策略；
- Markdown/HTML/SARIF Renderer；
- 完整 `report` 命令。

### Phase 3：ELF 深度分析

- Section/Segment/Dynamic/Relocation；
- 符号版本；
- TLS；
- DWARF；
- C++ RTTI/vtable 基础恢复。

### Phase 4：代码和图分析

- 反汇编；
- 函数边界；
- CFG；
- Call Graph；
- 图导出。

### Phase 5+：高级能力

- 安全识别；
- Binary Diff；
- 隔离动态分析；
- Fuzz 辅助；
- 可选 AI Provider。

## 6. 当前不应宣称的能力

在实现和验收前，项目文档、发布说明和 CLI 帮助不应宣称：

- V2 已经可以完成 ELF 深度扫描；
- `--jobs` 已实现并行；
- `--no-cache` 已控制真实缓存；
- Plugin Loader 可以自动加载第三方包；
- `report` 已生成 HTML 或执行完整 Schema 校验；
- 高级占位命令已经可用；
- V2 已替代 V1。

## 7. 发布门槛

将版本从 `2.0.0.dev0` 提升为可公开测试版本前，至少需要：

- File/ELF/Symbols/Strings/Security 基础 Analyzer；
- 至少一个内置 Profile；
- CLI 行为与文档一致；
- JSON Schema 固化；
- V1/V2 回归测试；
- License；
- 安装、升级和卸载说明；
- 样本与 Golden Test 策略。
