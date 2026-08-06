# SOInsight 快速开始

## 1. 选择版本

| 需求 | 推荐入口 |
|---|---|
| 立即使用已有 `.so` 扫描功能 | V1：`python3 main.py` |
| 查看或开发六大模块 CLI 框架 | V2：`python3 -m soinsight` / `soinsight` |
| 新增长期维护能力 | V2 namespaced Analyzer SDK |

V2 目前不能替代 V1 的真实扫描能力。

## 2. 环境

- V2：Python 3.10+、pip；
- 构建 Wheel：setuptools、wheel；
- V1 及未来基础分析：`readelf`、`nm`、`strings`（通常来自 binutils）。

## 3. 无安装运行 V2

```bash
PYTHONPATH=src python3 -m soinsight --version
PYTHONPATH=src python3 -m soinsight --help
PYTHONPATH=src python3 -m soinsight modules list
PYTHONPATH=src python3 -m soinsight modules show basic
PYTHONPATH=src python3 -m soinsight doctor
```

尝试一个领域命令：

```bash
PYTHONPATH=src python3 -m soinsight basic elf README.md --format json
```

当前具体 `basic.elf` Analyzer 未实现，预期返回 `ANALYSIS_PLAN_ERROR` 和退出码 3。

## 4. 安装开发版本

推荐在项目内创建 Python 虚拟环境后安装，避免系统 Python 目录权限问题：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e .
soinsight --help
soinsight modules list
```

开发依赖与测试：

```bash
# 若已激活 .venv，可直接复用该环境
python -m pip install -e '.[dev]'
python -m pytest -q
```

## 5. 构建 CLI Wheel

推荐命令：

```bash
./scripts/build_cli.sh
```

脚本会构建 Wheel、校验 `soinsight` CLI、六大模块包和 console entry point，并执行源码树版本冒烟测试。默认产物：

```text
dist/soinsight-2.0.0.dev0-py3-none-any.whl
```

安装产物：

```bash
python -m pip install --force-reinstall dist/soinsight-*.whl
soinsight --version
```

构建后直接安装：

```bash
./scripts/build_cli.sh --install
```

等价核心构建命令：

```bash
python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

## 6. 验证框架

```bash
soinsight modules list
soinsight plugins list
soinsight doctor
soinsight scan README.md --format json
```

预期：

- `modules list` 显示六个产品模块及其实现状态；
- `plugins list` 当前至少显示内置 `basic.file` Analyzer；
- `doctor` 以健康检查格式显示 `Product modules        6`；
- 默认 `scan README.md --format json` 会执行默认启用的 `basic.file` Analyzer。

## 7. 创建首个 YAML 配置

```bash
export SOINSIGHT_CONFIG_DIR="$PWD/.soinsight-configs"
soinsight config create quick
soinsight config set quick analysis.modules.basic '[file, elf]'
soinsight config validate quick
soinsight config use quick
soinsight config current
soinsight scan README.md --format json
```

由于真实 Analyzer 尚未迁移，最后一步可能返回 `ANALYSIS_PLAN_ERROR`；诊断中列出的 Analyzer 应来自 YAML，这说明选择链路已生效。完整说明见 [YAML 配置指南](configuration.md)。

## 8. 运行 V1

```bash
python3 main.py libexample.so
python3 main.py ./lib/
python3 main.py --help
```

V1 彩色输出可选依赖：

```bash
python3 -m pip install termcolor
```

## 9. 常见问题

### `No module named soinsight`

在仓库根目录使用：

```bash
PYTHONPATH=src python3 -m soinsight --help
```

或先创建并激活虚拟环境，再执行 `python -m pip install -e .`。

### `basic elf` 返回 `ANALYSIS_PLAN_ERROR`

领域命令已经建立，但 `basic.elf` 具体 Analyzer 尚未注册，这是当前阶段预期行为。

### 为什么 `modules` 有内容而 `plugins` 为空？

`modules` 是产品能力目录，`plugins` 是技术实现注册表。前者已经完成，后者等待迁移真实 Analyzer。
