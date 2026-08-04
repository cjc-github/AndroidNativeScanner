# SOInsight V2 架构说明

## 1. 架构目标

V2 使用“模块化单体 + 分层架构”，优先解决以下问题：

- CLI 不直接依赖具体 ELF 实现；
- 分析器之间通过声明式依赖组合；
- 事实采集、安全判断和输出渲染分离；
- 单个扩展异常不能导致整个进程无结构崩溃；
- 为缓存、并发、外部插件和新前端保留边界。

当前不引入 Web 服务、数据库或微服务。

## 2. 分层结构

```text
CLI Layer
    ↓
Application Layer
    ↓
Core Runtime
    ├── Target / Result / Finding / Diagnostic
    ├── Analyzer Registry
    ├── Dependency Planner
    ├── Scheduler
    ├── Rule Engine
    └── Result Aggregator
    ↓
Infrastructure
    ├── Config
    ├── Tool Runner
    ├── Artifact Store
    ├── Plugin Loader
    └── Serialization
    ↓
Renderer
```

### CLI Layer

位置：`src/soinsight/cli/`

职责：

- 定义命令和参数；
- 将 CLI 参数转换为 `AnalysisRequest` 和 `RuntimeConfig`；
- 选择 Renderer；
- 映射退出码。

CLI 不包含 ELF 解析逻辑。

### Application Layer

位置：`src/soinsight/application/`

职责：

- 解析和校验目标；
- 调用 Runtime；
- 将领域异常转换为 `ApplicationResponse`；
- 保持 CLI 与核心执行逻辑解耦。

### Core Layer

位置：`src/soinsight/core/`

这是 V2 的稳定核心，包括：

- 统一模型；
- Analyzer/Rule/Profile SDK；
- 依赖规划；
- 调度和聚合。

### Infrastructure Layer

位置：`src/soinsight/infrastructure/`

用于隔离易变化的实现细节：

- 文件和环境配置；
- subprocess；
- 文件缓存；
- 外部插件发现；
- 序列化。

### Renderer Layer

位置：`src/soinsight/renderers/`

把 `ApplicationResponse` 转换为 Text、JSON 或未来格式。Analyzer 不应自行打印报告。

## 3. 一次扫描的调用链

```text
1. CLI 解析 scan/file/elf 等命令
2. ConfigLoader 构造 RuntimeConfig
3. TargetResolver 校验单个文件并计算 SHA-256
4. Profile/--enable/单项命令确定 requested analyzer IDs
5. DependencyPlanner 递归补全 requires
6. Planner 检查 Analyzer 缺失和依赖环
7. SerialScheduler 按 stage 和拓扑顺序执行
8. Analyzer 将 AnalysisResult 写入 AnalysisContext
9. RuleEngine 消费成功的 Analyzer 结果并生成 Finding
10. ResultAggregator 生成 ScanResult
11. Renderer 输出 text/json
12. CLI 根据结果状态返回退出码
```

## 4. 依赖模型

Analyzer 使用 `AnalyzerMetadata.requires` 声明硬依赖：

```python
AnalyzerMetadata(
    id="elf",
    name="ELF Metadata",
    version="1.0.0",
    requires=("file",),
)
```

Planner 将请求：

```text
security
```

扩展为：

```text
file → elf → security
```

当前：

- 硬依赖参与 DAG；
- 检测循环依赖；
- 上游失败时下游标记为 `skipped`；
- `optional_requires` 已存在于元数据，但 Runtime 尚未做自动调度处理。

## 5. 状态模型

Analyzer 状态：

```text
pending, running, success, partial, skipped,
timeout, failed, cancelled, cached
```

当前 Scheduler 实际主要产生：

- `success`
- `failed`
- `skipped`
- `cancelled`

`timeout` 和 `cached` 已在模型中定义，等待 Runtime 集成。

聚合规则：

- 所有结果成功/缓存：`success`；
- 全部失败类状态：`failed`；
- 成功与失败混合：`partial`；
- 无 Analyzer：扫描框架为 `success`，附加 warning。

## 6. 扩展点

| 扩展点 | 当前接口 | 当前状态 |
|---|---|---|
| Analyzer | `Analyzer` | 可用 |
| Rule | `Rule` | 可用并已接入 Runtime |
| Profile | `ScanProfile` | 可注册，默认未内置 |
| Renderer | `Renderer` | Text/JSON 已实现 |
| Plugin Loader | `PluginLoader` | 空实现，占位 |
| Artifact Store | `ArtifactStore` | 文件实现存在，未接 Runtime |
| Scheduler | `SerialScheduler` | 串行可用 |

## 7. 包依赖约束

推荐依赖方向：

```text
cli → application → core
renderers → application/core
infrastructure → core contracts
analyzers → core + selected infrastructure
core 不依赖 cli
core 不依赖具体 analyzer
```

禁止：

- Analyzer 直接解析 CLI 参数；
- Rule 调用外部命令重新采集同一事实；
- Renderer 修改分析结果；
- Core 引入 V1 的协调器；
- Analyzer 通过 import 直接调用另一个 Analyzer 的 `analyze()`。

## 8. 当前与目标架构差距

尚需补齐：

1. 内置 Analyzer 和内置 Profile 注册；
2. `RuntimeConfig` 与文件/环境变量合并；
3. Artifact Store 缓存键、命中、失效和清理；
4. stage 内并发 Scheduler；
5. 插件 entry point 或插件目录发现；
6. JSON Schema 文件与兼容性测试；
7. 日志、指标和追踪 ID 输出；
8. V1 Compatibility Adapter。
