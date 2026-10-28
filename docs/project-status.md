# SOInsight V2 项目状态与路线图

**状态日期：2026-10-28**

## 1. 当前里程碑

> Phase 1B — 六大产品模块、共享技术框架、CLI 输出规范、`basic.file`/`basic.elf`/`basic.symbols`/`basic.dwarf`/`basic.types`/`basic.cpp`/`advanced.strings`/`security.hardening`/`security.dangerous-api`/`security.vulnerability`/`security.risk` 真实 Analyzer、跨域链路（`basic.file → basic.elf → security.hardening`、`basic.file → basic.elf → basic.symbols`、`basic.file → basic.elf → basic.dwarf`、`basic.file → basic.elf → basic.symbols/basic.dwarf → basic.types`）和内置 Profile 已完成；demangler 已在 5 个真实 C++ 共享库上与参考实现全量比对（1895 个 C++ 符号，0 无法解码、0 类型差异）；运行时控制（看门狗、取消令牌、进度观察者）已提前落地。

这里的"模块完成"指模块目录、能力 ID、CLI 路由和测试完成；`basic.file`/`basic.elf`/`basic.symbols`/`basic.dwarf`/`basic.types`/`basic.cpp`/`advanced.strings`/`security.hardening`/`security.dangerous-api`/`security.vulnerability`/`security.risk` 是已接入的真实 Analyzer，不代表 42 项业务能力已经实现。

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
- [x] 依赖 DAG、循环检测和 DAG stage Scheduler；
- [x] 异常隔离、依赖跳过和结果聚合；
- [x] Text/JSON Renderer；
- [x] ToolRunner、ArtifactStore 和 PluginLoader 边界；
- [x] Wheel 构建脚本和入口校验；
- [x] 内置 `basic.file` Analyzer（文件属性、SHA-256、Magic 与格式识别）；
- [x] 内置 `basic.elf` Analyzer（ELF 类、字节序、类型、机器、入口与段表计数）；
- [x] 内置 `basic.symbols` Analyzer（导出符号枚举 + 函数签名恢复）；
- [x] 纯 Python ELF 解析基础设施 `infrastructure/elf`（Header/Section/Symbol 表，无外部工具依赖）；
- [x] Itanium C++ ABI 符号 demangler（嵌套名、模板与替换、操作符、构造析构、local name、vtable/typeinfo/thunk）；
- [x] JNI  native 方法名解码器（包名/类名/方法名 + 重载参数类型）；
- [x] 内置 `security.hardening` Analyzer（基于 ELF/PHDR/符号表/GNU 属性事实生成 PIE/NX/RELRO、Canary、CFI、AArch64 PAC Finding）；
- [x] 内置 `basic.dwarf` Analyzer（DWARF 2-5 参数名/参数类型/返回类型/声明位置 + 限定名还原）；
- [x] 内置 `basic.types` Analyzer（ELF+DWARF 函数签名/全局变量/复合类型恢复 + DWARF 类型、成员、基类、枚举值、变量索引）；
- [x] 内置 `basic.cpp` Analyzer（RTTI/vtable/typeinfo/VTT/构造 vtable/thunk + 构造析构克隆码 + DWARF 继承/虚方法，仅定义符号产生类证据）；
- [x] 纯 Python DWARF 解析基础设施 `infrastructure/dwarf`（`.debug_info`/`.debug_abbrev`/`.debug_str`/`.debug_line_str`/`.debug_line`，无外部工具依赖）；
- [x] 内置 `security.dangerous-api` Analyzer（符号名精确匹配 + FORTIFY 归一化 + 严重度阈值）；
- [x] 第一条真实跨域链路：`basic.file → basic.elf → security.hardening`；
- [x] 第二条真实跨域链路：`basic.file → basic.elf → basic.symbols`；
- [x] 第三条真实跨域链路：`basic.file → basic.elf → basic.dwarf`（渲染层与 `basic.symbols` 联合）；
- [x] 内置 `quick`（`basic.file`/`basic.elf`）和 `security`（`security.hardening`）Profile；
- [x] Runtime 文件缓存（按“代码指纹 / 目标 sha256 / analyzer 版本”命中/写入，代码变更自动失效）；
- [x] DAG stage 并发执行（`jobs > 1` 时同 stage Analyzer 并行）；
- [x] Analyzer 超时看门狗、外部取消令牌和进度观察者；
- [x] Python entry point 插件发现（组 `soinsight.analyzers`）；
- [x] Markdown、HTML 报告渲染器；
- [x] SARIF 2.1.0 报告渲染器；
- [x] Text/Markdown/HTML 报告展示导出函数签名清单（含 DWARF 参数名联合）；
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
- [x] YAML 模块/功能点选择、排除、Runtime/输出/能力参数合并；
- [x] ELF 解析：Header/PHDR/Section/Symbol、ELF32 与 ELF64、截断与越界降级；
- [x] demangler：ABI 示例向量、真实 libstdc++/libc++/NDK 符号、畸形输入不回退；
- [x] demangler 与 `cpp_demangle` 参考实现交叉校验（dev 依赖，缺失时跳过）；
- [x] demangler 对真实共享库的全量比对（`scripts/categorise_real_sos.py`）；
- [x] JNI 解码：普通/重载/转义/默认包；
- [x] `basic.symbols`：导出函数、去重、stripped、选项、截断、非 ELF、JSON 可序列化；
- [x] `security.dangerous-api`：精确匹配、FORTIFY 归一化、无类型导出单独归类、选项与严重度阈值；
- [x] 运行时控制：Analyzer 超时看门狗、外部取消令牌、进度观察者（含缓存命中）、异常观察者不影响运行；
- [x] `basic.dwarf`：参数名/参数类型/返回类型/声明位置、限定名还原、行号表头文件名、截断与畸形降级。
- [x] `advanced.strings`：URL/敏感/Base64 分类、ELF 分节归属、截断诊断、非 ELF 目标可用；
- [x] `security.risk`：指纹去重、严重度/置信度/类别计数、V1 权重口径字符串指标、分档；
- [x] `security.*` 规则：sensitive-string / hardcoded-url / encoded-payload；缺失依赖时静默跳过。

当前自动化测试（`PYTHONPATH=src pytest`，pyelftools 可用、`cpp_demangle` 未装）：
`393 passed, 1 skipped`，此时 `test_demangler_oracle.py` 整模块不收集——装齐 dev 依赖
（`pip install -e '.[dev]'`）后该模块以及参考 demangler 比对用例会恢复收集。

### 真实共享库验证

用 `scripts/categorise_real_sos.py` 从 manylinux wheel 中取出真实 C++ 共享库（libproj、libtiff、libcurl、libsqlite3、libnghttp2，共 5 个）逐符号比对：

| 指标 | 数量 |
|---|---|
| 导出函数总数 | 2943 |
| C 符号（正确保持原样） | 1048 |
| C++ 符号成功 demangle | 1895 |
| 无法解码 | 0 |
| 与参考实现逐字节一致 | 1458 |
| 仅 special-name 显示格式不同（thunk/vtable 包装） | 437 |
| 类型/结构差异 | 0 |

该比对发现并修复了三类问题：重复的模板前缀候选导致后续替换索引整体偏移、`GTt`（TM clone）与构造函数模板（显式模板参数、抑制返回类型、前缀用类名）缺失、以及名字里含 `::` 的模板参数被错误切分。Python 扩展模块不适用此验证——它们以 hidden visibility 编译，只导出 `PyInit_*`。

### 导出枚举完备性审计

用 `scripts/audit_export_coverage.py` 以 pyelftools 独立读取 `.dynsym` 作为基准，逐库核对枚举结果：

| 指标 | 数量 |
|---|---|
| 基准导出函数（pyelftools） | 2943 |
| `basic.symbols` 报告 | 2943 |
| 遗漏 | 0 |
| 多报 | 0 |

边界情况单独用合成 ELF 覆盖（`test_analyzer_covers_every_export_table_entry`）：`STT_GNU_IFUNC`、`STB_WEAK`、`SHN_ABS`、`SHN_COMMON`、导入符号均已正确归类；**无类型（`STT_NOTYPE`）的全局导出**会被单独计入 `exported_unclassified` 并始终出现在 `unclassified_symbols` 中——它属于导出表且可被调用，但没有证据表明它是函数，因此不猜类型也不静默丢弃。`.dynsym` 中 `HIDDEN` 可见性符号按导出处理（记录中带 `visibility` 字段，用户可自行过滤）。

## 3. 已有外壳但未实现

| 范围 | 已有部分 | 缺少部分 |
|---|---|---|
| 六大模块 | Catalog、CLI、ID | `basic.cpp`/反汇编族/高级分析/动态/AI/Automation 等其余 Analyzer/Rule/Provider |
| `scan` | 目标解析、CLI/YAML 选择、Runtime、输出、`basic.file`、内置 Profile（`quick`/`security`） | 无 |
| Binary Diff | 双目标命令形态 | 多目标 Request 与 Diff 引擎 |
| Dynamic | 命令和能力定义 | 授权、沙箱、采集器 |
| AI | 命令和能力定义 | Provider、隐私、证据引用、成本治理 |
| Automation | 能力目录 | Workflow/CI/Fuzz 编排器 |
| Cache | 配置、FileArtifactStore、Runtime 命中/写入 | 失效/清理 |
| Plugins | Registry/Loader 边界、entry point 自动发现 | 兼容协议 |
| Reports | Text/JSON、Markdown、HTML、SARIF | Schema |
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
6. 增加非 ELF、损坏 ELF、工具缺失测试（✅ 非 ELF、截断 ELF、未知字段降级已覆盖；工具缺失待做）；
7. 与 V1 样本结果对照（待做）。

验收：

```bash
soinsight basic file libfoo.so
soinsight basic elf libfoo.so
soinsight security hardening libfoo.so
soinsight scan libfoo.so --module-available basic,security --format json
```

相关命令已输出真实结果，不再依赖测试注入。

## 5. 后续 Roadmap

### Phase 1B：V1 能力迁移

- `basic.symbols`（✅ 已完成：导出符号 + C++ demangle + JNI 解码）；
- `basic.dwarf`（✅ 已完成：参数名、参数类型、返回类型、声明位置；与 `basic.symbols` 在渲染层联合）；
- `security.dangerous-api`（✅ 已完成：依赖 `basic.symbols`，按符号名精确匹配）；
- `advanced.strings`（✅ 已完成：纯 Python 提取，任意文件可用；URL/敏感/Base64 分类 + ELF 分节归属 + 截断诊断；实现于 `analyzers/advanced.py` 与 `infrastructure/strings/`）；
- `security.risk`（✅ 已完成：依赖 `security.hardening` + `security.dangerous-api` + `advanced.strings`，按指纹去重、严重度/置信度/类别计数、V1 权重口径的字符串指标、可配置权重的风险分档；实现于 `analyzers/security.py`）；
- V1 URL/Secret/Base64 规则迁移（✅ 已完成：`rules/string_rules.py` 提供 `security.sensitive-string`、`security.hardcoded-url`、`security.encoded-payload` 三条内置规则，指纹格式 `sensitive:<label>:<value>` / `url:<value>` / `base64:<value>`）；
- V1 JNI 规则迁移（未做：JNI 导出统计已由 `basic.symbols` 以计数形式提供，命名建议类规则形态仍在设计）。

### 运行时控制（Phase 2 提前落地）

- [x] Analyzer 超时看门狗：`timeout_seconds` 此前只在 CLI/YAML 中透传，Runtime 从未读取；现在每个 Analyzer 在守护线程中执行，超时记 `ANALYZER_TIMEOUT` 并放弃该线程（Python 无法杀线程，因此用 daemon 线程，保证 Ctrl+C 仍能退出）；
- [x] 取消令牌：`CancellationToken` 已存在但无人设置；现在 `AnalysisRuntime.execute`/`AnalysisService.execute` 接受外部令牌，CLI 的 SIGINT 会取消后续 Analyzer，二次信号恢复默认行为以便立即中止；
- [x] 进度观察者：`ProgressObserver` 在 run/stage/analyzer 边界发事件，缓存命中也会报进度，观察者抛异常不会影响分析（这正是 Web UI 日志流需要的地基）。
- [x] CLI 接入：进度写在 stderr（`running basic.elf` / `basic.elf success 3 ms`），stdout 只保留可管道结果，`--quiet` 同时关闭进度行。

### Phase 2：共享基础设施

- JSON Schema 和兼容测试；
- 内置 Profile（✅ 已完成）；
- Runtime 缓存（✅ 已完成）；
- Markdown/HTML/SARIF（✅ 已完成）；
- 插件发现（✅ 已完成）；
- 并发（✅ 已完成）与资源预算。

### Phase 3：基础与高级分析深化

- DWARF、类型、C++；
- 反汇编、CFG、Call Graph、Data Flow；
- 算法、协议、格式、库、编译器和混淆识别。

### Phase 4：安全分析闭环

- 漏洞模式；
- 证据链、去重、置信度和风险评分；
- 软依赖（仅排序的可选依赖），支撑聚合类 Analyzer（`security.vulnerability` 等）在上游缺席时降级评分，也用于 `security.risk` 的非 ELF 降级；
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
- `basic.symbols` 能恢复 stripped 二进制的参数名或 DWARF 类型（ mangled name 与 JNI 名之外的类型信息不存在）；
- 动态分析会安全执行目标；
- AI 输出具备事实保证；
- 报告已支持完整 Schema。

## 7. 发布门槛

公开测试版本至少需要：

- 第一条跨域真实链路（✅ 已完成）；
- File/ELF/Symbols/Dwarf/Hardening/Dangerous API（✅ 已实现）+ Strings/Risk 规则链（✅ 已实现）；
- 内置 Profile（✅ 已完成）；
- CLI 与文档一致；
- JSON Schema；
- V1/V2 Golden 回归；
- License；
- 安装、升级、卸载和安全说明。
