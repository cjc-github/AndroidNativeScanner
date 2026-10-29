# 功能实现状态清单

**快照日期：2026-10-28**（基于代码与文档核实；`basic.types` 已提交（31965a7），`basic.cpp` 本次一并提交）

本文档把项目「已实现」与「可能未实现」的功能点整理为一页清单，便于交接与规划。详细路线图见 `project-status.md`，能力定义见 `module-system.md`。

---

## 一、已实现的功能点

### 1. V1 分析流水线（`python3 main.py`， legacy 保留）

| 功能 | 位置 | 说明 |
|---|---|---|
| ELF 头/段分析 | `src/analyzer/elf_analyzer.py` | 依赖外部 binutils（readelf） |
| 符号分析 | `src/analyzer/symbol_analyzer.py` | 依赖 nm |
| 字符串提取 | `src/analyzer/string_analyzer.py` + `src/utils.py` | 依赖 strings |
| URL 提取 | `src/analyzer/url_analyzer.py` | 批量扫描内置 |
| 敏感信息检测 | `src/analyzer/sensitive_analyzer.py` | 密码/密钥等模式 |
| Base64 字符串检测 | `src/analyzer/base64_analyzer.py` | 含可解码校验 |
| JNI 方法名解析 | `src/analyzer/jni_analyzer.py` | Java_ 前缀拆解 |
| 单文件/目录批量扫描 | `src/cli.py` | `-j` 并行、`-t` 超时、`-o reports` 输出、`-q` |
| 分项 + 汇总报告 | `analysis_coordinator.py`、`safe_write_report` | 各 analyzer 独立报告 |

### 2. V2 框架层（`soinsight`，六大共享机制）

- [x] 六大产品模块目录与命名空间：`basic`/`advanced`/`security`/`dynamic`/`ai`/`automation`，45 项能力 Catalog（`src/soinsight/modules/*/__init__.py`）
- [x] 领域化 CLI 命令树、`modules list/show`、`scan --module`（严格模式）与 `scan --module-available`（跨域展开）、隐藏 V1 兼容别名
- [x] Target/Result/Finding/Diagnostic 统一模型（`core/models/`）
- [x] Analyzer/Rule/Profile/Renderer SDK + Registry（`core/analyzer/`、`core/rules/`、`core/profiles/`）
- [x] 依赖 DAG、循环检测、stage 并发调度器（`jobs > 1`，`core/runtime/scheduler.py`）
- [x] 异常隔离、依赖跳过、结果聚合（`aggregator.py`）
- [x] Analyzer 执行计划 Planner（`planner.py`）
- [x] 运行时控制：超时看门狗（daemon 线程）、SIGINT 取消令牌（二次信号立即中止）、进度观察者（stderr 进度行、`--quiet` 关闭）（`core/runtime/runtime.py`、`progress.py`）
- [x] 文件缓存：按“代码指纹 / 目标 sha256 / analyzer 版本”三层命中/写入，代码变更自动失效；`--no-cache`、`--cache-dir`、`cache info/clean/prune`（`core/runtime/cache.py`）
- [x] ToolRunner、FileArtifactStore、PluginLoader 边界（`infrastructure/tools/`、`infrastructure/storage/`、`infrastructure/plugins/`）
- [x] entry point 插件自动发现（组名 `soinsight.analyzers`，`plugins list`）
- [x] YAML 配置体系：Schema、`config create/list/show/validate/use/current/clear/set/unset`、托管目录 + 活动配置、模块/能力选择、排除、runtime/output/capability options 合并（`infrastructure/config/`）
- [x] 内置 Profile：`quick`（basic.file/basic.elf）与 `security`（security.hardening）
- [x] CLI 输出规范：状态列、分组 help、`doctor`、`--quiet`、TTY 颜色、窄终端自适应、`report` 二次渲染
- [x] 退出码与错误语义：能力未实现 → `ANALYSIS_PLAN_ERROR`（预期外壳行为）

### 3. V2 已实现的真正 Analyzer 与 Rule（20/45 能力）

| 能力 ID | 内容 | 位置 |
|---|---|---|
| `basic.file` | 文件属性、SHA-256、Magic/格式识别 | `analyzers/basic.py` |
| `basic.elf` | ELF 类、字节序、类型、机器、入口、段表计数 | `analyzers/basic.py` |
| `basic.symbols` | `.dynsym`/`.symtab` 导出枚举 + C++ demangle + JNI 签名恢复 | `analyzers/symbols.py` |
| `basic.dwarf` | DWARF 2-5 参数名/类型/返回类型/声明位置，渲染层与 symbols 联合 | `analyzers/dwarf.py` |
| `basic.types` | 合并 ELF+DWARF 恢复函数签名、全局变量和 class/struct/union/enum 复合类型（含成员/基类/枚举值） | `analyzers/types.py` |
| `basic.cpp` | RTTI/vtable/typeinfo 符号 + 构造/析构克隆码 + 虚方法/继承（DWARF 基类与 RTTI 互证）；仅定义符号产生类证据，纯 C 结构不入清单 | `analyzers/cpp.py` |
| `basic.disasm` | 可执行分节拆分、函数边界（符号优先 + x86-64/AArch64 序言扫描补齐）与 Capstone 指令解码；解码器缺失/架构不支持时降级为边界事实 | `analyzers/disasm.py` + `infrastructure/disasm.py` |
| `basic.cfg` | 按函数构建控制流图：leader 切分基本块、`branch`/`cond`/`call`/`call_indirect`/`jump_indirect`/`fallthrough` 边分类、DFS 回边环检测；间接目标不猜测 | `analyzers/cfg.py` + `infrastructure/cfg.py` |
| `basic.callgraph` | 调用点解析为 local/import/indirect；PLT 桩经自身 GOT 槽匹配 `.rela.*` 恢复导入符号名，间接调用不带 callee；`callers_of` 反向索引与 `external_calls` 汇总 | `analyzers/callgraph.py` + `infrastructure/callgraph.py` |
| `basic.dataflow` | 函数内 use-def + 到达定义：按基本块聚合 `defs`/`uses`，`uses` 带 `reaching`；寄存器从操作数文本读取，子寄存器折叠到架构寄存器；前向数据流跨块传播 | `analyzers/dataflow.py` + `infrastructure/dataflow.py` |
| `basic.dynamic` | 动态链接事实：依赖清单、`SONAME`、RPATH/RUNPATH、构造/析构入口、符号版本与需求、重定位与导入计数 | `analyzers/dynamic_link.py` + `infrastructure/elf/dynamic.py` |
| `basic.xref` | 指令操作数到字符串字面量的交叉引用：逐函数重解码（x86 `rip-relative`/`absolute`、AArch64 `adr`/`adrp-add`/`register-load`、ARM 字面量池与 `movw`/`movt`），`exact`/`suffix` 匹配，控制流引用排除，寄存器追踪在写入与调用点失效；字符串表只收已加载的非代码分节，函数尺寸按分节裁剪 | `analyzers/xref.py` + `infrastructure/xref.py` |
| `security.hardening` | PIE/NX/RELRO + 栈保护(Canary)/CFI/AArch64 PAC（基于 ELF/PHDR/符号表/GNU 属性） | `analyzers/security.py` |
| `security.dangerous-api` | 符号名精确匹配危险 API（FORTIFY 归一化 + 严重度阈值） | `analyzers/security.py` |
| `advanced.strings` | 纯 Python 可见串提取（任意文件）+ URL/敏感/Base64 分类 + ELF 分节归属 + 截断诊断 | `analyzers/advanced.py` + `infrastructure/strings/` |
| `advanced.constants` | 已知算法常量表扫描（AES S-box、MD5/SHA 初值、CRC32、zlib deflate、Base64、ChaCha20 等）；要求全部特征字命中，记录偏移与分节 | `analyzers/constants.py` + `infrastructure/constants.py` |
| `advanced.algorithm` | 交叉判定算法：常量表命中 + 导入/导出符号名（OpenSSL/BoringSSL/zlib/mbedtls）+ 工具链与算法名字符串；多源证据标 `corroborated`，输出家族归类 | `analyzers/algorithm.py` + `infrastructure/algorithm.py` |
| `security.risk` | 三源聚合去重 + 严重度/置信度/类别计数 + V1 权重字符串指标 + 风险分档（权重可配） | `analyzers/security.py` |
| `security.dynamic-loading` | 动态加载风险：继承的 RPATH、相对与全局可写搜索路径、`DT_TEXTREL`、`DF_SYMBOLIC`/`DF_1_INTERPOSE`、无版本依赖 | `analyzers/dynamic_loading.py` |
| `security.vulnerability` | 把 `security.dangerous-api` 命中映射到 CWE（命令注入/缓冲区/格式串/权限等）并生成漏洞模式 Finding | `analyzers/security.py` |

内置 Rule（随规则引擎默认启用，依赖缺失时静默跳过）：`security.sensitive-string`、
`security.hardcoded-url`、`security.encoded-payload`（`rules/string_rules.py`，指纹格式
`sensitive:<label>:<value>` / `url:<value>` / `base64:<value>`）。

支撑基础设施（纯 Python、无外部工具依赖）：`infrastructure/elf`（Header/Section/PHDR/Symbol 表、Itanium C++ demangler、JNI 解码）、`infrastructure/dwarf`（`.debug_info/.debug_abbrev/.debug_str/.debug_line_str/.debug_line`）（`DwarfType`/`DwarfMember`/`DwarfBase`/`DwarfEnumValue`/`DwarfVariable` 与复合类型/变量索引）、`infrastructure/strings`（可见串提取与分类，迁移自 V1 口径）、`infrastructure/disasm`（Capstone 指令解码与函数边界恢复；Capstone 为可选依赖，缺失时仅保留边界事实）。

已验证事实（见 `project-status.md` §真实共享库验证）：5 个真实 C++ 共享库 2943 导出函数全覆盖，1895 个 C++ 符号 0 解码失败、0 类型差异。

### 4. 输出渲染

- [x] Text / JSON / Markdown / HTML / SARIF 2.1.0 五种格式（`renderers/`）
- [x] Markdown/HTML/Text 报告可导出函数签名清单（含 DWARF 参数名联合）
- [x] 从 JSON 中间报告 secondary 渲染（`soinsight report <file> --format …`）

### 5. Web 控制台（最新提交）

- [x] `web/server.py`：stdlib HTTP 服务，`/api/health`、`/api/modules`、`/api/samples`、`/api/analyze`；单能力（`capability=`）、多选能力（`mode=multi` + `capabilities=a,b,c`，映射 CLI `scan --enable`）与组合（`modules=`）三种模式；服务器路径（traversal 校验）或二进制上传（`X-Filename`）；子进程调用 `python -m soinsight --format json` 并回传 ScanResult；`POST /api/cancel` 可终止正在运行的子进程（返回 `分析已取消` 而非等满超时），超时上限由 `--timeout` 控制并在 `/api/health` 的 `analysis_timeout_seconds` 暴露；另提供异步任务接口 `POST /api/jobs` + `GET /api/jobs/<id>/log?offset=`（实时轮询日志）+ `GET /api/jobs/<id>/result`（完整 JSON），供深度分析台页面使用
- [x] 静态资源白名单：`_serve_static` 只放行 `CONTENT_TYPES` 里的扩展名，`server.py` / `start-web.bat` / `__pycache__/*.pyc` 等文件返回 404（此前可被直接下载源码）
- [x] `web/index.html`：拖拽上传/样本下拉/服务器路径三种目标来源；能力清单由 `/api/health` 的 `registered_analyzers` 动态生成（中文名映射见 `CAP_META`，未知 id 回退显示原名），支持任意多选 + 全选/清空，另带一个组合 scan 开关；结果区为横向 Tab（概览 / 每个 Analyzer 一页 / 原始 JSON），Tab 标签用中文名 + Analyzer ID，两端 `‹ ›` 箭头与 ←/→ 键切换，`aria-selected` 与 roving tabindex 同步；重跑前自动清空上一次结果；运行中可点「停止分析」取消；计时显示「已用 X s / 上限 Y s」，超时与取消分别给出明确提示；勾选的能力与服务器路径写入 `localStorage`，刷新后自动恢复；每个 Analyzer 面板内附「文本化结果」折叠块
- [x] 结果导出：符号表（按当前搜索/语言筛选）与发现项可一键导出 CSV（UTF-8 BOM，Excel 直接打开不乱码；以 `= + - @` 开头的单元格做公式注入转义）

- [x] `web/so-scan.html`：独立"深度分析台"页面——选择 .so 文件（点击/拖拽）→ 一键启动全量 scan → 实时滚动日志 → 结果摘要（退出码/耗时/风险分档/发现项计数/能力状态 chips（按结果动态生成）+ 文件/ELF/符号/字符串/风险/发现项分区 + 每个 Analyzer 的「文本化结果」区块）→ 下载 JSON；控制台头部提供入口链接
- [x] `web/start-web.bat` Windows 启动脚本；云端适配（`PORT`/`0.0.0.0` + `requirements.txt`）

本地集成测试通过：上传、路径安全、静态资源白名单（源码不可下载）、非 ELF（exit 5 `INVALID_ELF`）、错误 400/403/404、取消与超时终止子进程等均覆盖。

### 6. 构建、脚本与测试

- [x] 可编辑安装（`setup.py`/`setup.cfg`）与 console script；Wheel 构建脚本 `scripts/build_cli.sh`（`--install` 一键）
- [x] 辅助脚本：`categorise_real_sos.py`（真实库 demangle 全量比对）、`audit_export_coverage.py`（pyelftools 基准导出覆盖率审计）、`crosscheck_sample_demangle.py`、`demangle_gap_summary.py`、`find_dwarf.py`
- [x] 自动化测试套件（`tests/unit` + `tests/integration`）：完整 dev 环境（含 `cpp_demangle`/`pyelftools`）**513 passed, 9 skipped**（跳过均为参考 demangler 自身无法解析的 C/JNI 符号，预期）；缺 `cpp_demangle` 的普通环境会整模块跳过 `test_demangler_oracle.py`（`PYTHONPATH=src pytest` 可直接跑）
- [x] 文档守卫测试 `test_documentation_status.py`（防止文档与实现漂移）

---

## 二、可能未实现的功能点（按域列出）

### 1. 能力外壳（Catalog + CLI 存在，返回 `ANALYSIS_PLAN_ERROR`）

以下 25/45 项能力**只有目录和命令外壳，没有真实 Analyzer**：

| 模块 | 未实现能力 |
|---|---|
| `basic`（0/12） | —（`basic` 十二项能力全部已实现） |
| `advanced`（5/8） | `advanced.protocol`、`advanced.file-format`、`advanced.library`、`advanced.compiler`、`advanced.obfuscation` |
| `security`（0/5） | — |
| `dynamic`（5/5） | `dynamic.trace`、`dynamic.arguments`、`dynamic.memory`、`dynamic.syscalls`、`dynamic.coverage`（全部） |
| `ai`（8/8） | `ai.function-name`、`ai.parameter-semantics`、`ai.struct-recovery`、`ai.module-identification`、`ai.algorithm-explanation`、`ai.protocol-explanation`、`ai.vulnerability-explanation`、`ai.assembly-explanation`（全部） |
| `automation`（7/7） | `automation.binary-diff`、`automation.fuzz-target`、`automation.harness`、`automation.seed`、`automation.crash-cluster`、`automation.report`、`automation.workflow`（全部） |

`advanced.strings`、`advanced.constants`、`advanced.algorithm`、`security.risk`、`security.vulnerability`、`security.dynamic-loading`、`basic.cpp`、`basic.disasm`、`basic.cfg`、`basic.callgraph`、`basic.dataflow`、`basic.dynamic`、`basic.xref` 与 V1 的 URL/Secret/Base64 规则迁移已完成（见上表）；
下一步建议是 `advanced.file-format`（magic 扫描无需反汇编）与 `advanced.library`。

完整清单与实现顺序见 [未完成分析能力与技术债](pending-capabilities.md)。

### 2. 框架层缺口（外壳已建，实现不完整）

- [ ] **Binary Diff**：只有两个 `old new` 目标参数的命令形态；无多目标 Request 与 Diff 引擎
- [ ] **动态分析执行**：无授权门、沙箱/隔离执行器、Trace/参数/内存/系统调用/覆盖率采集器；静态结果与动态结果关联
- [ ] **AI 分析**：无 Provider 抽象（本地优先策略）、隐私防护、证据引用、模型版本与成本治理
- [ ] **Automation**：无 Workflow、CI Gate、Fuzz 编排器、批处理流水线
- [ ] **软依赖（order-only dependency）**：调度器的 `requires` 既是排序依据也是跳过闸门；聚合类 Analyzer（`security.risk`、未来的 `security.vulnerability`）需要"仅保证顺序、上游缺席时降级为空集"的可选依赖。当前 `security.risk` 在非 ELF 目标上随链跳过是有意行为（规则报告仍在，缺风险分档）
- [ ] ~~缓存治理~~：✅ 已解决——缓存键加入代码指纹（源码变更自动失效），`cache info/clean/prune` 可清理旧版本条目
- [ ] **插件协议**：entry point 发现已实现，但与外部插件的兼容协议未定义
- [ ] **报告 Schema**：无机器可校验的 JSON Schema（`docs/cli-output-schema.md` 只是文档描述，未提供 `.schema.json` 与兼容测试）
- [ ] **并行资源预算**：stage 内并发有，跨阶段总资源/内存预算无
- [ ] **目录扫描**：V2 TargetResolver 只接受单文件（`target_resolver.py` 报 "expects a single file"）；目录批量扫描仅 V1 有
- [ ] ~~doctor 误报~~：✅ 已解决——缺 binutils 报 info 而非 warning（binutils 仅 V1 legacy 管线需要，十一项已实现 Analyzer 均为纯 Python）

### 3. 工程化缺口

- [ ] **License 文件**：公开分发前必须补齐
- [ ] **CI**：无 `.github/workflows`，测试不自动跑
- [ ] **V1 测试**：`main.py`/`src/cli.py`/`src/analyzer/*` 零测试覆盖
- [ ] **V1/V2 Golden 回归**：无跨版本结果对照机制
- [ ] **安装/升级/卸载与安全说明**：README 缺少三件套说明
- [ ] **`in/` 25MB 验证样本**：被 `.gitignore` 忽略，真实库审计结论在新克隆无法复现
- [ ] **`.workbuddy/`**：未跟踪也未忽略，归属待定

### 4. 能力边界（即便已实现，也存在声明的限制）

- `basic.symbols` 无法为 stripped 二进制恢复参数名/DWARF 类型（mangled name 之外的类型信息不存在）；
- `basic.dwarf` 只在有调试信息的二进制上有意义；
- `security.hardening` 已覆盖 PIE/NX/RELRO、Canary、CFI 与 AArch64 PAC；Canary/CFI 通过对符号表是否存在 `__stack_chk_fail`/`__cfi_*` 引用进行检测（未引用即视为缺失），PAC 通过 `.note.gnu.property` 的 `GNU_PROPERTY_AARCH64_FEATURE_1_AND` 位检测；
- `security.dangerous-api` 按符号名精确匹配，不含调用点上下文证据；
- 未实现能力在 `scan` 严格模式（`--module`）下整域报错，属框架阶段预期行为。

---

## 三、使用建议

- 验证已实现能力：`PYTHONPATH=src python3 -m soinsight scan libfoo.so --module-available basic,security`
- 查询能力目录：`soinsight modules list`（已实现/外壳一目了然）
- 详细状态与验收标准：`docs/project-status.md`
- 迁移映射：`docs/migration-v1-to-v2.md`
