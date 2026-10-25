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

## 注意事项

- 六大模块共 42 项能力，已实现的是 `basic.file`、`basic.elf`、`basic.symbols`、`basic.dwarf`、`security.hardening`、`security.dangerous-api`；调用未实现的能力会返回 `ANALYSIS_PLAN_ERROR`（退出码 3）。
- `--module` 是严格展开（要求模块内能力全部已实现），日常请用 `--module-available`。
- V1 旧入口仍可用：`python3 main.py libfoo.so`。

## 更多文档

- 原详细使用文档（快速开始/使用手册/命令参考/YAML 配置）：`docs/archive/`
- 模块体系与 42 项能力清单：`docs/module-system.md`
- 项目状态与路线图：`docs/project-status.md`
- 设计与扩展开发：`design/design_v2.0.md`、`docs/extension-development.md`
