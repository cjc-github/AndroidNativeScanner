# SOInsight 快速使用

SOInsight（命令 `soinsight`）对 Linux/Android ELF 动态库（`.so`）做本地静态分析。本页只覆盖最简用法；完整参数、YAML 字段与设计细节见 `docs/archive/` 与 `design/`。

## 1. 安装

源码目录内免安装运行：

```bash
PYTHONPATH=src python3 -m soinsight --help
```

可编辑安装（推荐，先建虚拟环境）：

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e '.[dev]'
soinsight --version
```

## 2. 环境自检

```bash
soinsight doctor
soinsight modules list
```

## 3. 常用命令

```bash
# 文件与 ELF 基础信息
soinsight basic file libfoo.so
soinsight basic elf libfoo.so

# 导出符号与函数签名（C++ demangle、JNI 解码）
soinsight basic symbols libfoo.so

# DWARF 调试信息（参数名/参数类型、返回类型、声明位置）
soinsight basic dwarf libfoo.so

# 安全加固与危险 API
soinsight security hardening libfoo.so
soinsight security dangerous-api libfoo.so

# 组合扫描：跨模块，只运行已实现的能力
soinsight scan libfoo.so --module-available basic,security
```

## 4. 输出

```bash
--format text|json|markdown|html|sarif   # 默认 text
-o result.json                           # 结果写入文件
--quiet                                  # 成功时完全静默（关闭进度行与文本结果）
```

## 5. 可复用 YAML 配置

```bash
soinsight config create quick-security
soinsight config set quick-security analysis.modules.basic '[file, elf]'
soinsight config use quick-security
soinsight scan libfoo.so
```

## 6. Web 控制台（可选）

不想敲命令时，可启动一个本地网页控制台，在浏览器里选择 .so 文件、勾选能力后一键分析，结果以卡片形式展示（ELF 头、符号表、发现项、DWARF 等）。

```bash
# 启动：在项目根目录执行
python web/server.py            # 默认 http://127.0.0.1:8791

# 或直接双击 web/start-web.bat（Windows）
```

用浏览器打开提示的地址即可。支持三种目标来源：**拖拽 / 点击上传 .so 文件**、**填写服务器上已有的绝对路径**、**直接选 `in/` 目录里的样本**。分析后端就是 `soinsight` CLI（`--format json`），所以 CLI 能跑的能力，网页里都能跑。

> 仅监听本机 `127.0.0.1`，不上传任何数据到外部网络；非 ELF 文件或非法路径会被直接拒绝。

## 注意事项

- 六大模块共 45 项能力，已实现的是 `basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`basic.types`、`basic.cpp`、`basic.disasm`、`basic.cfg`、`basic.callgraph`、`basic.dataflow`、`basic.dynamic`、`basic.xref`、`advanced.strings`、`advanced.constants`、`advanced.algorithm`、`advanced.protocol`、`advanced.file-format`、`advanced.library`、`advanced.compiler`、`advanced.obfuscation`、`security.hardening`、`security.dangerous-api`、`security.vulnerability`、`security.risk`、`security.dynamic-loading`、`automation.fuzz-target`、`automation.harness`；调用未实现的能力会返回 `ANALYSIS_PLAN_ERROR`（退出码 3）。
- `--module` 是严格展开（要求模块内能力全部已实现），日常请用 `--module-available`。
- V1 旧入口仍可用：`python3 main.py libfoo.so`。

## CI 用法（Gate 与基线）

```bash
# 建立基线并确认当前状态（按 high 阈值判定，退出码 6 表示未通过）
soinsight scan libfoo.so --module-available basic,security \
  --fail-on high --update-baseline .soinsight/baseline.json

# CI 中只拦新问题
soinsight scan libfoo.so --module-available basic,security \
  --fail-on high --baseline .soinsight/baseline.json
```

基线内的问题仍会出现在报告里（标 `suppressed`/`[baselined]`），只是不再阻断构建。

## 动态分析（默认拒绝执行）

`dynamic.*` 会执行目标，因此默认拒绝。只有在配置中显式授权后才会继续判定：

```yaml
# 例如写在 ~/.config/soinsight/config.yaml 或项目配置里
dynamic_execution:
  authorized: true
  allow_targets: ["/opt/samples/libfoo.so"]   # 可选白名单
```

```bash
soinsight dynamic trace libfoo.so   # 未授权 → not-authorized；已授权但无沙箱 → no-sandbox
```

隔离靠探测（`bwrap` > `firejail` > `docker` > `unshare`），探测不到就拒绝，**不会**在宿主上裸跑。
当前 `dynamic.trace` 只产出沙箱执行计划（含超时/内存上限），不启动进程、不采集事件。

## 版本对比（Binary Diff）

```bash
soinsight diff old.so new.so            # 符号级：新增 / 移除 / 移动 / 大小变化
soinsight diff old.so new.so --format json
```

纯静态对比，秒级出结果；函数体级与 CFG 级差异不在范围内。

## 更多文档

- 原详细使用文档（快速开始/使用手册/命令参考/YAML 配置）：`docs/archive/`
- 模块体系与 45 项能力清单：`docs/module-system.md`
- 项目状态与路线图：`docs/project-status.md`
- 设计与扩展开发：`design/design_v2.0.md`、`docs/extension-development.md`
