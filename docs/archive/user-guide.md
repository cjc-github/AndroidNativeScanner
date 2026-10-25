# SOInsight V2 使用手册

> 本文档对应 2026-10-24 的仓库实现。V2 已搭建六大产品模块和 CLI 框架，并实现 `basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`security.hardening`、`security.dangerous-api` 真实 Analyzer；其余能力保持 `partial` 或 `planned`。

## 1. 查看模块

```bash
soinsight modules list
soinsight modules show basic
soinsight modules list --format json
```

六个模块为 `basic`、`advanced`、`security`、`dynamic`、`ai`、`automation`。完整能力表见[模块体系](../module-system.md)。

## 2. 运行单项能力

```bash
soinsight basic file libfoo.so
soinsight basic elf libfoo.so --format json
soinsight basic symbols libfoo.so
soinsight basic dwarf libfoo.so --format json
soinsight advanced strings libfoo.so
soinsight security hardening libfoo.so
soinsight security dangerous-api libfoo.so
soinsight dynamic trace libfoo.so
soinsight ai function-name libfoo.so
soinsight automation fuzz-target libfoo.so
```

当前命令会进入统一 Runtime。已注册的能力（`basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`security.hardening`、`security.dangerous-api`）执行真实分析；未注册的能力（如 `advanced.strings`、`basic.types`、`security.vulnerability`）结构化返回 `ANALYSIS_PLAN_ERROR`。

### 2.1 导出函数签名（`basic symbols`）

```bash
soinsight basic symbols libfoo.so
soinsight basic symbols libfoo.so --format json
soinsight basic symbols libfoo.so --format markdown -o signatures.md
```

`basic.symbols` 枚举共享对象导出的函数，并恢复二进制本身保留的签名信息：

| 来源 | 可恢复信息 |
|---|---|
| `.dynsym` / `.symtab` | 符号名、bind、可见性、地址、大小、导入/导出 |
| Itanium C++ mangled name | 命名空间、类、方法名、参数类型（模板函数含返回类型） |
| JNI native 方法名 | Java 包名、类名、方法名、重载方法的参数类型 |

### 用 DWARF 补上参数名

`.dynsym` 永远给不出参数名——它只编码类型。`basic.dwarf` 解析 DWARF 调试信息，把参数名、参数类型、返回类型和声明位置补回来，并在渲染层与 `basic.symbols` 按 mangled name 联合：

```bash
soinsight scan libfoo.so --enable basic.file,basic.elf,basic.symbols,basic.dwarf
```

```text
Symbols:
  Symbol tables        .dynsym
  Exported functions   3
  Demangled            1
  JNI methods          1
  With parameter names 2
  Signatures:
    int add(int a, int b)
    int MyClass::process(char const* buffer, unsigned int length)
    com.example.Foo.nativeInit
```

`With parameter names` 是命中了 DWARF 的导出函数数量；没有调试信息的符号仍显示原来的类型级签名。`basic.dwarf` 也可以单独运行，用于查看调试信息本身：

```bash
soinsight basic dwarf libfoo.so --format json
```

调试信息是可选事实：stripped 发布包没有 `.debug_*` 段时记为 `has_debug_info: false`，不是错误；解析失败记 `DWARF_UNREADABLE` 警告，不影响其余分析。

### 危险 API 检测

`security.dangerous-api` 在 `basic.symbols` 之上检测危险 API：

```bash
soinsight security dangerous-api libfoo.so
```

```text
Findings: 12
  [high] Dangerous API imported: mprotect
  [low] Dangerous API imported: unlink
  [high] Dangerous API imported: sprintf
```

规则表是数据而非代码，按符号名**精确**匹配（不会因子串误报，`memcpy`/`malloc`/`printf` 这类到处都有的原语被刻意排除）；`__strcpy_chk` 这类 FORTIFY 变体和前导下划线会先归一化再匹配。导入意味着"能触达"，导出意味着"对外提供"——分析器不做反汇编，所以这是能力而非使用证据，Finding 的 confidence 字段已说明这一点。

可用选项（`capability_options.security.dangerous-api`）：

| 选项 | 默认 | 说明 |
|---|---|---|
| `include_imports` | `true` | 检测导入的危险 API |
| `include_exports` | `true` | 检测导出的危险 API |
| `min_severity` | `info` | 严重度阈值，`low`/`medium`/`high`/`critical` |

枚举范围与 `readelf --dyn-syms` / `nm -D --defined-only` 一致：`.dynsym` 中已定义、`GLOBAL`/`WEAK` 绑定、类型为 `STT_FUNC`/`STT_GNU_IFUNC` 的符号。已用 pyelftools 独立读取 `.dynsym` 作基准核对过 5 个真实共享库的 2943 个导出函数，0 遗漏、0 多报。

三类符号单独归类，不混入函数列表：

- **导出数据符号**（`STT_OBJECT`）：需 `include_data_symbols: true` 才列出；
- **导入符号**（`SHN_UNDEF`）：需 `include_imports: true` 才列出；
- **无类型导出**（`STT_NOTYPE`，常见于未写 `.type` 的汇编代码）：**始终**计入 `counts.exported_unclassified` 并列入 `unclassified_symbols`——它属于导出表且可被调用，但没有证据表明它是函数，因此不猜类型也不静默丢弃。

文本输出示例：

```text
Symbols:
  Symbol tables        .dynsym
  Exported functions   3
  Demangled            2
  JNI methods          1
  Signatures:
    com.example.Foo.nativeInit
    foo::bar(int)
    std::vector<int, std::allocator<int>>::push_back(int const&)
```

签名恢复的边界：

- stripped 发布包只有 `.dynsym`，本地符号与 DWARF 参数名不可用；
- C++ 函数的返回类型只在函数模板和类型转换操作符的 mangled name 中编码；构造函数模板虽编码了返回类型，但按参考 demangler 的约定不展示（构造函数返回 void）；
- JNI 重载后缀只含参数类型，不含返回类型；
- 无法解释的 mangled name 原样返回，不做猜测；
- 模板参数（`T_`/`T0_`/…）按外层模板参数解析；解析结果本身也会成为替换候选，因此同一类型可能占据两个替换索引——这与参考 mangler 一致。

输出格式与 GNU `c++filt` 对齐：模板实参列表闭合前加一个空格（`std::vector<int, std::allocator<int> >`），仅在最后一个实参本身以 `>` 结尾时才加，避免与 `>>` 移位运算符混淆。special-name（vtable/typeinfo/thunk/TM clone）使用本项目自己的可读写法，与 `c++filt` 的花括号形式不同。

可通过 YAML `capability_options` 调整行为：

```yaml
schema_version: 1
name: symbol-scan
analysis:
  capabilities: [basic.symbols]
capability_options:
  basic.symbols:
    demangle: true              # 解释 C++ mangled name
    jni_decode: true            # 解释 JNI native 方法名
    include_data_symbols: false # 额外列出导出数据符号
    include_imports: false      # 额外列出导入符号
    max_functions: 10000        # 导出函数上限（1..100000）
```

输出中的 `counts` 各字段含义：`exported_functions`（函数）、`exported_data`（数据）、`exported_unclassified`（无类型导出，始终统计）、`imports`（导入）、`local`（本地符号）。

### 运行时控制

| 参数 | 说明 |
|---|---|
| `-j, --jobs N` | 同一 stage 内并行执行的 Analyzer 数（默认 1） |
| `--timeout SECONDS` | 单个 Analyzer 的超时；与 Analyzer 自身的 `timeout_seconds` 取较紧者。超时记 `ANALYZER_TIMEOUT` 诊断并放弃该 Analyzer，不会中断整轮分析 |
| `--fail-fast` | 出现失败即停止调度后续 stage |
| `--no-cache` | 忽略本轮缓存 |
| `-q, --quiet` | 成功时不输出分析文本（同时关闭 stderr 上的进度行） |
| `-v, --verbose` | 详细输出 |

进度写在 **stderr**（`running basic.elf` / `basic.elf success 3 ms`），stdout 只保留可管道的结果；`--quiet` 会关闭它。按 Ctrl+C 会取消尚未开始的 Analyzer（已记 `CANCELLED`），再按一次立即中止。

## 3. 综合扫描

```bash
soinsight scan libfoo.so
soinsight scan libfoo.so --format json -o result.json
```

当前目标必须是存在的单个文件。TargetResolver 会记录真实路径、名称、大小、SHA-256 和扫描时间。

按产品模块选择：

```bash
soinsight scan libfoo.so --module-available basic,security --format json
```

`--module-available` 只展开模块中已注册 Analyzer 的能力；`--module` 是严格展开，模块内若有未实现的能力会返回 `ANALYSIS_PLAN_ERROR`（退出码 3）并指出缺失项。

精确选择能力实现：

```bash
soinsight scan libfoo.so --enable basic.file,basic.elf
```

`--module` 是用户侧领域选择，`--enable` 是 Analyzer ID 级别的精确选择。两者同时使用时会合并并去重，也可以与 YAML 配置共同使用。

## 4. 使用 Profile

```bash
soinsight scan libfoo.so --profile quick
soinsight scan libfoo.so --profile security
```

Profile 用于保存跨域能力组合。默认 CLI 已内置：

- `quick`：`basic.file`、`basic.elf`；
- `security`：`security.hardening`（含其依赖链）。
规划中的 Profile：

- `deep`：基础和高级静态分析；
- `ci`：稳定、可复现、适合风险门禁的组合。

## 5. 自动化能力

```bash
soinsight automation binary-diff old.so new.so
soinsight automation report result.json
soinsight automation workflow manifest.json
```

领域内的 `automation report/workflow` 代表产品自动化能力；顶层 `report` 当前只是技术性的 JSON 重格式化命令。后续二者应通过统一结果和工作流引擎衔接。

## 6. 输出

```bash
soinsight basic elf libfoo.so --format text
soinsight basic elf libfoo.so --format json
soinsight scan libfoo.so --format json --output result.json
```

当前支持 Text、JSON、Markdown、HTML、SARIF。

## 7. 环境诊断

```bash
soinsight doctor
soinsight doctor --format json
```

输出包含：SOInsight 版本、Python、产品模块数量、已注册 Analyzer 数量，以及 `readelf`、`nm`、`strings` 路径。

## 8. 模块与插件的区别

```bash
soinsight modules list   # 产品“准备提供什么”
soinsight plugins list   # 当前进程“实际加载了什么 Analyzer”
```

在当前阶段，模块数量为 6、能力数量为 42，而 Analyzer 数量为 6（`basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`security.hardening`、`security.dangerous-api`）。这不是冲突：外部产品框架已建立，其余具体实现仍在迁移中。

## 9. 报告、缓存和 YAML 配置

```bash
soinsight report result.json --format json -o normalized.json
soinsight cache info
soinsight config create quick-security
soinsight config set quick-security analysis.modules.basic '[file, elf]'
soinsight config set quick-security analysis.modules.security '[hardening]'
soinsight config validate quick-security
soinsight config use quick-security
soinsight scan libfoo.so
```

也可以不激活配置，直接指定托管名称或外部路径：

```bash
soinsight scan libfoo.so --config quick-security
soinsight scan libfoo.so --config ./configs/quick-security.yaml
```

YAML 可以订制模块、模块内功能点、跨模块 capability、排除项、Runtime、输出和能力专属选项。显式 CLI 参数优先于 YAML；显式领域命令只运行该项能力，不会被 YAML 扩大。完整 Schema 和管理方式见 [YAML 配置指南](configuration.md)。

当前其他限制：

- `report` 不做完整 SOInsight Schema 校验；
- ArtifactStore 尚未接入 Runtime；
- `--jobs > 1` 已支持同 stage Analyzer 并发；资源预算和取消协调待做。

## 10. 常见诊断

| 诊断码 | 含义 |
|---|---|
| `NO_ANALYZERS_SELECTED` | 没有默认 Analyzer 或明确选择 |
| `INVALID_TARGET` | 目标不存在或不是当前支持的单文件 |
| `INVALID_CONFIGURATION` | jobs、timeout 等非法 |
| `INVALID_ANALYSIS_CONFIG` | YAML 不存在、格式错误或引用未知能力 |
| `MODULE_NOT_FOUND` | `--module` 包含未知模块 |
| `PROFILE_NOT_FOUND` | Profile 未注册 |
| `ANALYSIS_PLAN_ERROR` | Analyzer 缺失、依赖缺失或 DAG 规划失败 |
| `ANALYZER_EXCEPTION` | Analyzer 执行异常 |
| `DEPENDENCY_FAILED` | 必需上游未成功 |
| `RULE_EXCEPTION` | Rule 执行异常 |
| `INVALID_ELF` | 目标不是可解析的 ELF 镜像 |
| `NO_SYMBOL_TABLE` | 镜像没有动态或常规符号表（`basic.symbols` 降级） |
| `SYMBOLS_TRUNCATED` | 导出函数数量超过 `max_functions`，列表被截断 |
| `ANALYZER_TIMEOUT` | Analyzer 超过时间预算被放弃（结果记为 `timeout`） |
| `DWARF_UNREADABLE` | 调试信息存在但无法解析 |