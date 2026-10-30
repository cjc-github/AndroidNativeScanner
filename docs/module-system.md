# SOInsight V2 模块体系

## 1. 模块定义

SOInsight V2 以 `design/design_v2.0.md` 为唯一主设计基线。一级模块固定为六个能力域：

| 模块 ID | 中文名 | 能力数 | CLI 前缀 | 定位 |
|---|---|---:|---|---|
| `basic` | 基础分析 | 12 | `soinsight basic` | 建立二进制、ELF、代码结构和统一 IR 基础事实 |
| `advanced` | 高级分析 | 8 | `soinsight advanced` | 从基础事实识别字符串、算法、协议、工具链等语义 |
| `security` | 安全分析 | 5 | `soinsight security` | 形成安全 Finding、证据和风险结论 |
| `dynamic` | 动态分析 | 5 | `soinsight dynamic` | 在授权与隔离环境中采集运行时证据 |
| `ai` | AI 分析 | 8 | `soinsight ai` | 消费已有证据进行语义恢复与解释 |
| `automation` | 自动化 | 7 | `soinsight automation` | 组合能力形成 Diff、Fuzz、报告和 CI 工作流 |

前 40 项能力来自 V2 原始设计；`automation.report` 和 `automation.workflow` 是为了兑现“自动化报告、批处理和 CI 集成”目标而补充的编排能力；`basic.dynamic`、`security.dynamic-loading` 与 `basic.xref` 是为补齐动态链接事实、动态加载风险判定和代码到数据的交叉引用而新增的能力。

## 2. 能力目录

### 2.1 基础分析

| 命令 | 稳定能力 ID | 能力 | 状态 |
|---|---|---|---|
| `basic file` | `basic.file` | 文件分析 | 已实现 |
| `basic elf` | `basic.elf` | ELF 解析 | 已实现 |
| `basic symbols` | `basic.symbols` | Symbol 解析 | 已实现 |
| `basic dwarf` | `basic.dwarf` | DWARF 解析 | 已实现 |
| `basic types` | `basic.types` | 类型恢复 | 已实现 |
| `basic cpp` | `basic.cpp` | C++ 恢复 | 已实现 |
| `basic disasm` | `basic.disasm` | 反汇编 | 已实现 |
| `basic cfg` | `basic.cfg` | CFG 恢复 | 已实现 |
| `basic callgraph` | `basic.callgraph` | Call Graph 恢复 | 已实现 |
| `basic dataflow` | `basic.dataflow` | Data Flow 分析 | 已实现 |
| `basic dynamic` | `basic.dynamic` | 动态链接解析 | 已实现 |
| `basic xref` | `basic.xref` | 交叉引用 | 已实现 |

`basic.symbols` 采集 `.dynsym`/`.symtab` 符号事实，并从 Itanium C++ mangled name 恢复参数类型、从 JNI native 方法名恢复 Java 包名/类名/方法名与参数类型。其依赖链为 `basic.file → basic.elf → basic.symbols`；mangled name 与 JNI 名之外的签名信息（DWARF 参数名、完整类型）不存在于二进制中，不做推测。

`basic.dwarf` 解析 DWARF 2-5 调试信息（`.debug_info`/`.debug_abbrev`/`.debug_str`/`.debug_line_str` 与 `.debug_line` 行号表头），提取 `DW_TAG_subprogram` 的参数名、参数类型、返回类型与 `DW_AT_decl_file`/`DW_AT_decl_line`，并按父 DIE 链还原类/命名空间限定名；类外定义沿 `DW_AT_specification`/`DW_AT_abstract_origin` 链继承声明属性，同一符号的声明/定义记录按 linkage 合并（DWARF5 的行号表格式与 0 基文件/目录索引按规范处理）。其依赖链为 `basic.file → basic.elf → basic.dwarf`；调试信息缺失记为事实（`has_debug_info: false`），畸形记 `DWARF_UNREADABLE` 警告，不影响其余分析。渲染层会把 DWARF 参数名按 mangled name 联合回 `basic.symbols` 的签名。

`basic.types` 把 ELF 符号表和 DWARF 调试信息合并成轻量类型模型：函数签名、全局变量，以及 class/struct/union/enum 复合类型（含成员、基类、枚举值）。它按 `linkage_name` 把 DWARF 函数/变量事实与 `basic.symbols` 合并（DWARF 优先），stripped 或缺少调试信息时仍保留符号表事实并标记类型未知（`unknown`），不做猜测。其依赖链为 `basic.file → basic.elf → basic.symbols/basic.dwarf → basic.types`；数据结构见 `infrastructure/dwarf/structures.py`。

`basic.cpp` 把链接层证据恢复成 C++ 结构事实：`_ZTV*`/`_ZTI*`/`_ZTS*`/`_ZTT*` 符号给出 vtable/typeinfo/typeinfo name/VTT 及所属类，`_ZTC*` 记为构造 vtable 清单，`_ZTh*`/`_ZTv*` thunk 作为扁平证据记录（不在类记录中映射回类）；构造/析构函数由 demangler 的 constructor/destructor kind 归类（支持 C1/C2/C3/C4/C5 与 D0/D1/D2/D4/D5 克隆码），虚方法与继承来自 DWARF（基类、offset、accessibility、virtuality）。类记录标注证据来源（`dwarf`/`rtti`/`symbols`）并三方互证；只有本镜像定义的符号产生证据（导入的 `__cxxabiv1` 运行时符号不算），纯 C 结构（无基类/特殊成员/vtable/RTTI 证据）不进入类清单。其依赖链为 `basic.file → basic.elf → basic.dwarf → basic.types → basic.cpp`；能力边界是链接层恢复：不含调用点证据，无法还原源码语义。

`basic.disasm` 解码可执行分节并恢复函数边界，是 `basic.cfg`/`basic.callgraph`/`basic.dataflow` 的共同前置。它不声明 `requires`：自己解析 ELF 镜像，因此可在 `basic.file → basic.elf → basic.symbols` 链之外单独运行。事实分三类：`code_regions`（可执行分节拆分）、`functions`（地址/长度/来源/指令数/未解码字节）与 `instructions`（分页数组，按上限截断）。边界先取符号表中已定义的函数符号（同一地址/尺寸在 `.dynsym` 与 `.symtab` 重复时取 `.symtab`），符号空隙再用 x86-64（`endbr64`、`push rbp; mov rbp,rsp`）与 AArch64（`stp x29,x30,[sp,…]`、`sub sp`）序言扫描补齐；序言命中不与符号边界重复。指令解码走 Capstone（可选依赖，与 `cpp_demangle` 同策略）：缺失时报 `DISASM_DECODER_UNAVAILABLE` 警告并保留边界事实；机器类型无解码器（`DISASM_UNSUPPORTED_ARCH`）或无可执行分节（`DISASM_NO_CODE_REGIONS`）时同样只降级不失败。规模由能力选项 `max_functions`/`max_instructions` 控制，越界记 `DISASM_TRUNCATED`。

`basic.cfg` 在 `basic.disasm` 的指令流之上按函数构建控制流图：基本块由「入口、直接跳转目标、终结指令的下一条」三类 leader 切分，边按终结指令分类为 `branch`/`cond`/`call`/`call_indirect`/`jump_indirect`/`fallthrough`。间接跳转与间接调用不猜目标，只记 `*_indirect` 边；`call` 的返回边记到 fall-through 块，被调方作为调用图事实由 `basic.callgraph` 处理。回边环用深度优先回边检测报告为块起址环，不可约 CFG 降级为「未报告环」而非错误结论。它同样不声明 `requires`（自解析 ELF 并复用反汇编事实），Capstone 缺失或无可执行分节时报 `CFG_NO_DECODER`/`CFG_NO_CODE_REGIONS` 警告并返回空图；规模由 `max_functions`/`max_instructions` 控制，越界记 `CFG_TRUNCATED`。数据结构见 `infrastructure/cfg.py`。

`basic.callgraph` 解析调用点为 `call_edges`（caller/callee/`callee_kind: local/import/indirect`）并给出 `callers_of` 反向索引与 `external_calls` 外部调用汇总。直接调用按函数符号表解析为 `local`；落到 PLT 桩的调用经桩自身的 GOT 槽（x86-64 `jmp [rip+disp]`、AArch64 `adrp`+`ldr` 对）匹配 `.rela.*` 重定位恢复导入符号名，记为 `import`；间接调用（寄存器/内存目标）只记 `indirect` 且不带 callee，不猜测。PLT 桩起点从指令形态读取，不假设固定步长，因此 PLT0、`.plt.sec` 与 IRELATIVE 布局同样成立。降级与截断语义同 `basic.cfg`（`CALLGRAPH_NO_DECODER`/`CALLGRAPH_NO_CODE_REGIONS`/`CALLGRAPH_TRUNCATED`，`max_functions`/`max_instructions`/`max_edges`）。数据结构见 `infrastructure/callgraph.py`。

`basic.dataflow` 在 `basic.cfg` 的基本块之上做函数内（intra-procedural）use-def 与到达定义分析。寄存器位置从指令操作数文本读取而非解码器摘要：目标操作数为写、其余寄存器为读，子寄存器折叠到架构寄存器（`eax`→`rax`、`w0`→`x0`），内存操作数只贡献基址寄存器。事实按基本块聚合为 `defs`/`uses`，`uses` 携带 `reaching` 到达定义列表；跨块传播是前向数据流（按前驱重算 `in`，块内最后一次定义 kill 入口值），在最长无环路径上每块一轮收敛。函数间传播不在能力范围内（`scope: intra-procedural`），规模由 `max_functions`/`max_instructions`/`max_pairs` 控制，越界记 `DATAFLOW_TRUNCATED`；降级语义同 `basic.cfg`（`DATAFLOW_NO_DECODER`/`DATAFLOW_NO_CODE_REGIONS`）。数据结构见 `infrastructure/dataflow.py`。

`basic.xref` 把指令操作数还原成数据地址，再与镜像中已加载分节的可见串对齐，回答“这个字符串在哪条指令上被引用”。它在 `basic.disasm` 的代码区域与函数边界之上逐函数重解码（Capstone detail 模式读取操作数），函数之外的空隙（PLT 桩等）再补扫：编译器会把常量池嵌进 `.text`，整段线性解码会在常量池处失去同步。引用形态按架构读取——x86-64 的 `rip-relative`/`absolute`/`immediate`，AArch64 的 `adr`、`adrp`+`add` 页内偏移对以及寄存器追踪得到的 `register-load`，ARM 的 `movw`/`movt` 半字拼装与 PC 相对字面量池。地址正好落在串首记 `exact`，落在串中间记 `suffix`。跳转与调用目标指向代码而不是数据，不参与字符串匹配。寄存器追踪只在单个解码块内有效且不建模控制流：被追踪的页一旦遇到非页算术的写入（含 `w0`/`x0` 这类别名，按折叠后的寄存器名判定）即失效，调用点按 AAPCS64（x0-x18）与 AAPCS（r0-r3、r12）丢弃可能被 callee 破坏的值——留着过期页会报出指令根本不指向的地址。字符串表只收带 `SHF_ALLOC` 且不带 `SHF_EXECINSTR` 的分节：代码段里的展开表字节看起来像串但不是字面量；函数尺寸越出其所在分节时按分节裁剪，避免把下一分节的字节当指令解码。输出是事实而非结论（`xrefs` 记录串、串地址、所属分节、指令地址、引用形态与匹配形态，另有计数汇总），引用含义的判断留在 `security.*` 规则。Capstone 缺失（`XREF_DECODER_UNAVAILABLE`）或机器类型无解码器（`XREF_UNSUPPORTED_ARCH`）时保留字符串侧事实并把引用数记为 0，无可执行分节记 `XREF_NO_CODE_REGIONS`；规模由 `min_length`/`max_strings`/`max_xrefs` 控制，越界记 `XREF_STRINGS_TRUNCATED`/`XREF_TRUNCATED`。数据结构见 `infrastructure/xref.py`。

### 2.2 高级分析

| 命令 | 稳定能力 ID | 能力 | 状态 |
|---|---|---|---|
| `advanced strings` | `advanced.strings` | 字符串分析 | 已实现 |
| `advanced constants` | `advanced.constants` | 常量分析 | 已实现 |
| `advanced algorithm` | `advanced.algorithm` | 算法识别 | 已实现 |
| `advanced protocol` | `advanced.protocol` | 协议识别 | 已实现 |
| `advanced file-format` | `advanced.file-format` | 文件格式识别 | 已实现 |
| `advanced library` | `advanced.library` | 第三方库识别 | 已实现 |
| `advanced compiler` | `advanced.compiler` | 编译器识别 | 已实现 |
| `advanced obfuscation` | `advanced.obfuscation` | 混淆识别 | 已实现 |

`advanced.strings` 对任意文件（含非 ELF）做纯 Python 可见串提取并去重计数，可选
URL/敏感凭据/Base64 分类并归属到 ELF 分节；截断时给出 `STRINGS_TRUNCATED` /
`STRINGS_INPUT_TRUNCATED` 诊断，规模上限通过能力选项
（`min_length`/`max_strings`/`max_hits_per_category`/`max_scan_bytes`/`classify`）
控制。

`advanced.constants` 扫描数据段中的已知算法常量表（AES S-box、MD5/SHA 初值、CRC32 多项式、zlib deflate 基表、Base64 字母表、ChaCha20 sigma 等）。签名要求**所有**特征字都出现才算命中，单个巧合字不产生结论；命中记录首个特征字的文件偏移与所属分节。它同样对任意文件可用（非 ELF 目标没有分节归属，记为 `null` 而不是失败），输入超过 `max_scan_bytes` 时报 `CONSTANTS_INPUT_TRUNCATED` 并说明尾部未扫描；每算法命中数由 `max_hits_per_algorithm` 限制。这里只报告"常量表存在"这一事实，算法判定与用途推断由 `advanced.algorithm` 负责。数据结构见 `infrastructure/constants.py`。

`advanced.algorithm` 把三类证据交叉起来判定算法：`infrastructure/constants.py` 的常量表命中、`basic.symbols` 的导入/导出符号名（`EVP_`/`BIO_`/`CRYPTO_` → OpenSSL，`mbedtls_`、`BORINGSSL`、`inflate`/`deflate` 等）与文件中的字符串线索（`AES-256-GCM`、`OpenSSL 1.1.1` 这类）。每条证据单独记录来源与命中的字符串，同一个字符串可同时支持多个算法；证据来源超过一个时标 `corroborated`，单一来源标 `single`——前者比后者可信，但都不等于"确认使用"。输出 `algorithms`（算法名/家族/强度/证据）、`families`（crypto/hash/compression/encoding/library 归类）与各来源的命中计数，输入超过 `max_scan_bytes` 时报 `ALGORITHM_INPUT_TRUNCATED`；符号与字符串数量分别由 `max_symbols`/`max_strings` 与 `min_length` 控制。数据结构见 `infrastructure/algorithm.py`。

`advanced.file-format` 扫描原始字节里的格式魔数，既识别目标自身的外层格式（偏移 0），也识别嵌入在其中的资源与载荷（ZIP/PNG/JPEG/GIF/PDF/DEX/APK 签名块/ELF/Mach-O/Java class/gzip/bzip2/xz/7z/SQLite/RIFF/Ogg）。命中记录格式、类别、偏移与 `verified`——后者表示魔数之外的结构校验（JPEG 是否自带 EOI、ZIP 是否有中央目录尾、DEX 是否带三位版本号）也通过，只是证据强度，不是结论。ELF 目标会把偏移归到所属分节；`CAFEBABE` 同时是 fat Mach-O 与 Java class 的魔数，两种解释都作为事实列出并各自校验。规模由 `max_scan_bytes`/`max_hits` 控制，越界记 `FORMAT_INPUT_TRUNCATED`。数据结构见 `infrastructure/formats.py`。

`advanced.library` 把链接层证据汇成第三方库判定：`DT_NEEDED`/SONAME、符号命名空间前缀（`_ZSt`、`_ZN6google8protobuf`、`EVP_*`、`inflate`/`deflate`）与版本串（`OpenSSL 1.1.1`、`zlib 1.2.11`）。指纹表覆盖运行时（libc++/libstdc++/gnustl）、加密（OpenSSL/BoringSSL/mbedTLS/libsodium）、压缩（zlib/liblzma/bzip2）、图像（libpng/libjpeg/libwebp/freetype）、网络（libcurl/c-ares）、序列化（protobuf/json-c/SQLite）、XML（libxml2/expat）、媒体（FFmpeg）与日志（Android liblog）。单源命中标 `single`，两种及以上来源标 `corroborated`；非 ELF 目标只用字符串证据。数据结构见 `infrastructure/library.py`。

`advanced.compiler` 识别编译工具链：从 `.comment` 段与 note 段读取编译器横幅（`GCC: (GNU) 9.4.0`、`Android clang version 14.0.6`、`rustc`、`Swift version`、`Emscripten`、`MSVC`），用运行时符号（`_Unwind_Resume`、`__aeabi_*`、`__clang_call_terminate`、`swift_*`、`__android_log_*`）佐证，并从匹配到的整行横幅中提取版本号。`.comment` 被剥离时退回全文件可见串扫描；同时报告 build-id 与 `.note.android.ident` 是否存在。单源 `single`、多源 `corroborated`。数据结构见 `infrastructure/compiler.py`。

`advanced.protocol` 用协议关键字与消息头常量（`GET /`、`HTTP/1.1`、`MQTT`、`Sec-WebSocket-Key`、`grpc-status`、`RTSP/1.0` 等）加网络侧符号（`SSL_read`/`SSL_CTX_new`、`MQTTClient_*`、`grpc_*`、`PQconnectdb`、`redisCommand`）做链接级协议特征识别，覆盖 Web/传输/消息/RPC/媒体/数据库/IoT/VPN 共 21 个指纹。语义级识别需要动态证据，不在此能力范围内；单源 `single`、多源 `corroborated`。数据结构见 `infrastructure/protocol.py`。

`advanced.obfuscation` 报告加壳与混淆证据：UPX/ASPack/Petite 壳签名、VMProtect/Themida 保护器横幅、OLLVM 特征串与 `__llvm` 辅助符号，以及分节熵值超过阈值（默认 7.0，可由 `entropy_threshold` 调整）的可疑高熵分节。控制流平坦化判定需要比较恢复出的 CFG 形状，属于后续能力，这里不做字节级猜测。信号带类别（packer/protector/obfuscator/packing）与证据，规模由 `max_scan_bytes`/`max_symbols`/`max_section_bytes` 控制，越界记 `OBFUSCATION_INPUT_TRUNCATED`。数据结构见 `infrastructure/obfuscation.py`。

### 2.3 安全分析

| 命令 | 稳定能力 ID | 能力 | 状态 |
|---|---|---|---|
| `security hardening` | `security.hardening` | 安全保护检测 | 已实现 |
| `security dangerous-api` | `security.dangerous-api` | 危险 API 检测 | 已实现 |
| `security vulnerability` | `security.vulnerability` | 漏洞模式识别 | 已实现 |
| `security risk` | `security.risk` | 风险评分/评估 | 已实现 |
| `security dynamic-loading` | `security.dynamic-loading` | 动态加载风险 | 已实现 |

`security.vulnerability` 依赖 `security.dangerous-api`，把危险 API 链接事实按符号名映射到
CWE 类别（命令注入/缓冲区溢出/格式化字符串/路径/权限等），生成带证据链的漏洞模式
Finding，并输出 `counts_by_cwe`/`counts_by_severity` 计数。它基于链接级事实推断，不含
调用点上下文证据——`basic.callgraph`/`basic.dataflow` 实现后可提升证据等级。

`security.risk` 聚合 `security.hardening`、`security.dangerous-api` 的发现项与
`advanced.strings` 分类事实：按指纹（缺失指纹时按 `rule:message`）去重统计
严重度/置信度/类别，按 V1 口径加权 URL/凭据/Base64 指标，叠加
critical=12/high=8/medium=5/low=2/info=1（可用能力选项
`security.risk.severity_weights` 覆盖）算出风险分并分档
low/medium/high/critical。三个内置规则
`security.sensitive-string`、`security.hardcoded-url`、`security.encoded-payload`
随规则引擎自动运行，缺失 `advanced.strings` 数据时静默跳过。

风险评分需要三条上游全部成功：非 ELF 目标（或任一上游失败/跳过）会让
`security.risk` 以 `DEPENDENCY_FAILED` 整体跳过，此时字符串事实仍会被规则引擎
转成发现项，但**没有风险分档**——这是有意设计而非缺漏。若希望"缺上游即按
空集降级评分"，要先给调度器引入"仅用于排序的可选依赖（软依赖）"，规划于
`security.vulnerability` 阶段一并落地。

### 2.4 动态分析

| 命令 | 稳定能力 ID | 能力 | 状态 |
|---|---|---|---|
| `dynamic trace` | `dynamic.trace` | Runtime Trace | 已接入（默认拒绝执行，仅出计划） |
| `dynamic arguments` | `dynamic.arguments` | 参数采集 | 外壳 |
| `dynamic memory` | `dynamic.memory` | 内存分析 | 外壳 |
| `dynamic syscalls` | `dynamic.syscalls` | 系统调用分析 | 外壳 |
| `dynamic coverage` | `dynamic.coverage` | 覆盖率分析 | 外壳 |

### 2.5 AI 分析

| 命令 | 稳定能力 ID | 能力 |
|---|---|---|
| `ai function-name` | `ai.function-name` | 函数命名 |
| `ai parameter-semantics` | `ai.parameter-semantics` | 参数语义恢复 |
| `ai struct-recovery` | `ai.struct-recovery` | 结构体恢复 |
| `ai module-identification` | `ai.module-identification` | 模块识别 |
| `ai algorithm-explanation` | `ai.algorithm-explanation` | 算法解释 |
| `ai protocol-explanation` | `ai.protocol-explanation` | 协议解释 |
| `ai vulnerability-explanation` | `ai.vulnerability-explanation` | 漏洞解释 |
| `ai assembly-explanation` | `ai.assembly-explanation` | 汇编自然语言解释 |

### 2.6 自动化

| 命令 | 稳定能力 ID | 能力 | 状态 |
|---|---|---|---|
| `automation binary-diff OLD NEW` | `automation.binary-diff` | Binary Diff | 已实现（符号级） |
| `automation fuzz-target TARGET` | `automation.fuzz-target` | Fuzz Target 识别 | 已实现（静态版） |
| `automation harness TARGET` | `automation.harness` | Harness 生成 | 已实现（模板型） |
| `automation seed TARGET` | `automation.seed` | Seed 生成 | 外壳 |
| `automation crash-cluster TARGET` | `automation.crash-cluster` | Crash 聚类 | 外壳 |
| `automation report TARGET` | `automation.report` | 报告自动化 | 外壳 |
| `automation workflow TARGET` | `automation.workflow` | 批处理、Profile、CI Gate 和工作流编排 | 外壳 |

`automation.binary-diff` 比较 two ELF 镜像的**已定义函数符号集**（`diff OLD NEW` 或 YAML `binary_diff.old_path`/`new_path`）：按 mangled name 匹配，报告新增/移除/移动（同地址不同）/大小变化，函数体级与 CFG 级对比不在此能力范围。它是双输入能力：不进默认扫描集，单独通过 `diff` 命令或显式 `--enable` 运行。纯静态，秒级出结果。

`automation.harness` 把 `automation.fuzz-target` 的候选变成 libFuzzer 风格的 C 模板：第一个缓冲区参数接到 fuzz 输入，识别出的长度参数接 `size`，其余参数填零值。它不猜第二缓冲区、回调与输出指针——这些以 `HARNESS_TEMPLATE_INCOMPLETE` 警告列出，等人工补桩。原型的返回类型：签名已带返回类型就原样 `extern`；签名只有 `name(...)` 时用元数据 `return_type`，两者都没有则按 `int` 假设并明说。喂了缓冲区但没识别到长度参数时同样警告（否则模板传 0，fuzz 不到东西）。模板只生成源码文本，不编译也不执行；`--format json` 携带完整 `source`。

`automation.fuzz-target` 只消费静态事实，不执行目标：导出函数与 JNI 方法都是可直达的入口，`basic.types` 提供参数类型，名称里的解析/读取语义提高排序。参数按**形状**归类（`buffer`/`size`/`out-pointer`/`struct`/`callback`/`scalar`）：`size_t`、定宽整型按类型判定，而 `int mode` 只有在参数名像长度（`len`/`size`/`count`…）时才算长度——不然会把模式参数当成缓冲区长度。评分只用于排序（JNI 45 / 解析类 35 / 普通导出 10，缓冲区+长度对 +25，指针参数各 +5，无参数 −10，回调参数 −5），输出标 `heuristic: true`，不是「可 fuzz」结论。

## 3. 产品模块与技术扩展点

两套视图正交存在：

```text
产品视图（用户看到）
基础分析 / 高级分析 / 安全分析 / 动态分析 / AI 分析 / 自动化

技术视图（开发者实现）
CLI / Application / Analyzer / Rule / Planner / Scheduler /
Result Model / Renderer / Artifact Store / Plugin Loader / Tool Runner
```

一个产品能力通常由一个或多个 Analyzer、Rule、外部工具适配器和 Renderer 协作完成。例如“危险 API 检测”属于安全分析，不因为它内部使用 Symbol Analyzer、Call Graph Analyzer 和 Rule Engine 就被拆成多个产品模块。

## 4. 跨域依赖规则

允许跨域依赖，但必须通过稳定能力 ID、DAG 和标准化结果完成：

```text
security.dangerous-api
  requires: basic.symbols

ai.vulnerability-explanation
  consumes: security.vulnerability / security.risk findings

automation.harness
  consumes: basic.types, advanced.protocol, dynamic.coverage
```

`security.dangerous-api` 硬依赖 `basic.symbols`：它按符号名精确匹配导入/导出的危险 API，FORTIFY 变体（`__strcpy_chk`）和前导下划线先归一化再匹配。`basic.callgraph` 是它的**软依赖**（`optional_requires`）：当同一次扫描里存在调用图时，导入型命中会带上调用点数量与地址，证据标 `call-site`；没有调用图时照常工作，证据标 `linkage`。`security.vulnerability` 把这些调用点继续带进自己的证据，但置信度仍是 MEDIUM——调用点证明「被使用」，不证明「参数可控」。

约束：

1. Analyzer 通过 `requires` 声明硬依赖，通过 `optional_requires` 声明软依赖；
2. Planner 补全硬依赖、检查循环，并把软依赖作为纯排序约束：软依赖不会因为被声明而被拉进计划，只有它因别的原因（被直接请求或被硬依赖拉入）出现在计划里时才要求先跑；未注册的软依赖被忽略，不报错；
3. 下游从 `AnalysisContext` 读取统一结果：硬依赖用 `require()`，软依赖用 `optional()` 并在缺席时降级；
3a. 缓存按（代码指纹、目标 sha256、Analyzer ID+版本、**参与的可选依赖集合**）分键——同一目标上有无调用图会产出不同事实，不能互相复用；结果还依赖宿主或配置状态的 Analyzer（例如 `dynamic.trace` 取决于授权与已安装的沙箱）必须声明 `cacheable=False`，运行时既不读取也不写入它的缓存条目；
4. 禁止一个模块直接 import 并调用另一个模块 Analyzer 的 `analyze()`；
5. AI 能力优先解释已有证据，不重复执行安全或基础分析；
6. 自动化能力负责组合，不复制底层分析逻辑。

`dynamic.trace` 是动态族的第一个接入点，它把「能不能执行」变成代码而不是文档：
配置里没有 `dynamic_execution.authorized: true` 就返回 `state: not-authorized`；
授权后若探测不到 `bwrap`/`firejail`/`docker`/`unshare`，返回 `state: no-sandbox` 并拒绝执行；
两者都满足时返回 `state: planned`，给出包裹后的 argv、超时与内存上限，但 `executed: false`——
采集器与 `dlopen` 驱动尚未接入（`infrastructure/execution.py`）。

## 5. 当前实现状态

已实现：

- 六大模块注册目录 `src/soinsight/modules/`；
- 45 项能力定义及命名空间校验；
- 软依赖（`optional_requires`）调度、软依赖缺席降级与按参与依赖分键的缓存；
- 领域命令树；
- `modules list/show`；
- `scan --module-available basic,security` 对单目标已注册能力进行展开（`--module` 为严格模式，模块内能力未全部实现时返回 `ANALYSIS_PLAN_ERROR`）；
- 单目标能力到 Runtime 的路由；
- 开发期旧扁平命令隐藏兼容别名；
- 11 个真实 Analyzer：`basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`basic.types`、`basic.cpp`、`advanced.strings`、`security.hardening`、`security.dangerous-api`、`security.vulnerability`、`security.risk`。

未实现：

- 45 项能力对应的具体 Analyzer/Rule/Provider；
- 双目标及复杂输入能力的统一 Request 模型；
- 动态分析隔离执行器；
- AI Provider、隐私策略和成本控制；
- 自动化工作流执行引擎。

因此“模块已搭建”表示产品目录、CLI 外壳和技术接入点已建立，不表示业务分析结果已经可用。

## 6. YAML 中的模块与能力引用

YAML 的 `analysis.modules` 使用模块 ID 和模块内 command，例如 `basic: [file, elf]`；`analysis.capabilities`、`analysis.exclude` 和 `capability_options` 使用完整 ID，例如 `security.hardening`。这样既保持用户侧六大模块结构，也保持 Runtime 的稳定 namespaced 能力标识。详见 [YAML 配置指南](archive/configuration.md)。
