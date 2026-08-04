# SOInsight V1 到 V2 迁移指南

## 1. 迁移目标

迁移不是把 `src/analyzer/` 原样复制到 `src/soinsight/analyzers/`，而是将 V1 能力拆分到 V2 的职责边界中：

```text
V1 BaseAnalyzer/analyze
        ↓
V2 Analyzer（事实提取）
        ↓
V2 Rule（风险判断）
        ↓
V2 Renderer（输出）
```

迁移期间必须保持 `python3 main.py` 可用。

## 2. 概念映射

| V1 | V2 |
|---|---|
| `BaseAnalyzer` | `core.analyzer.Analyzer` |
| `AnalysisCoordinator` | `AnalysisRuntime` + Planner + Scheduler |
| `analyze()` 返回任意结构 | `AnalysisResult` |
| `summarize()` 风险分 | Rule + Finding + Aggregator |
| Analyzer 内共享 context 参数 | `AnalysisContext.require/optional` |
| Analyzer 自行输出/汇总 | Renderer |
| 顺序硬编码 | `AnalyzerMetadata.requires` DAG |
| 报告字典 | `ScanResult` Schema |

## 3. 推荐迁移顺序

### Step 1：FileAnalyzer

提供所有后续模块需要的基础文件事实：

- 文件类型/Magic；
- 大小、SHA-256；
- 是否为 ELF；
- ELF class/endianness 的最小识别。

虽然 `TargetResolver` 已计算大小和 SHA-256，但 FileAnalyzer 应定义面向 Analyzer 的正式文件结果协议。

### Step 2：ElfAnalyzer

迁移 `src/analyzer/elf_analyzer.py`，依赖 `file`，先覆盖 V1 已有 ELF Header 字段。

### Step 3：SymbolsAnalyzer

迁移符号提取，但把“危险函数意味着多少风险分”的逻辑移入 Rule。

### Step 4：StringsAnalyzer

统一字符串结果，作为 URL、敏感信息、Base64 等 Analyzer 的共享上游，避免重复执行 `strings`。

### Step 5：检测器与安全规则

建议拆分：

```text
strings
├── detect.urls
├── detect.secrets
└── detect.base64

symbols
├── detect.dangerous-imports
└── detect.jni
```

检测器返回候选事实，Rule 再生成 Finding。

### Step 6：Profile

当基础 Analyzer 稳定后，增加：

- `quick`：file + elf；
- `default`：基础元数据 + symbols + strings；
- `security`：default + detectors + rules。

## 4. Adapter 还是重写

适合 Adapter：

- V1 逻辑稳定；
- 返回值容易转换；
- 没有大量终端输出和全局状态；
- 能通过依赖注入控制 timeout。

适合重写：

- 同一外部命令被多个 Analyzer 重复调用；
- 分析和风险评分严重耦合；
- 直接写报告文件；
- 通过隐式字典字段共享状态；
- 异常处理和 timeout 不明确。

## 5. 兼容策略

迁移初期：

```text
main.py                  → V1
python3 -m soinsight     → V2
```

不要让 V2 入口直接代理全部 V1 Coordinator，否则会把旧耦合带入新 Runtime。

可以在 `src/soinsight/compatibility/` 中提供细粒度 Adapter：

```text
compatibility/
├── v1_elf_adapter.py
├── v1_symbols_adapter.py
└── result_mapping.py
```

每个 Adapter 仍必须返回标准 `AnalysisResult`。

## 6. 单模块迁移验收表

- [ ] Analyzer ID 和版本已确定；
- [ ] 输入、输出字段形成文档；
- [ ] 硬依赖写入 `requires`；
- [ ] 不直接打印、不直接生成最终报告；
- [ ] timeout 和外部工具错误结构化；
- [ ] 风险判断已移动到 Rule；
- [ ] V1 与 V2 对同一样本的核心事实一致；
- [ ] CLI text/json 测试通过；
- [ ] V1 回归测试通过；
- [ ] 文档和 Roadmap 更新。

## 7. 第一条纵向链路建议

```text
TargetResolver
    ↓
FileAnalyzer
    ↓
ElfAnalyzer
    ↓
Hardening Rule
    ↓
Finding
    ↓
JSON Renderer
```

该链路完成后，才能认为 V2 从“框架可运行”进入“具备最小实际分析能力”。
