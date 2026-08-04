# SOInsight 快速开始

## 1. 版本选择

| 需求 | 推荐入口 |
|---|---|
| 立即使用已有 `.so` 扫描功能 | V1：`python3 main.py` |
| 查看或开发 V2 CLI 框架 | V2：`python3 -m soinsight` / `soinsight` |
| 新增长期维护的分析能力 | 优先使用 V2 Analyzer SDK |

V1 和 V2 当前并存。V2 尚未迁移具体分析器，因此不能替代 V1 的实际扫描功能。

## 2. 环境要求

V2：

- Python 3.10+
- `pip`
- 构建 Wheel 时需要 `setuptools` 和 `wheel`

V1 以及未来基础 ELF Analyzer 需要：

- `readelf`
- `nm`
- `strings`

Ubuntu/Debian 通常可以通过以下方式安装：

```bash
sudo apt-get install python3 python3-pip binutils
```

## 3. 获取并进入项目

```bash
git clone <repository-url>
cd AndroidNativeScanner
```

## 4. 运行 V2

### 4.1 无安装运行

```bash
PYTHONPATH=src python3 -m soinsight --version
PYTHONPATH=src python3 -m soinsight --help
PYTHONPATH=src python3 -m soinsight doctor
```

### 4.2 可编辑安装

```bash
python3 -m pip install -e .
soinsight --version
soinsight --help
```

开发环境：

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

### 4.3 构建 CLI Wheel

推荐使用仓库脚本：

```bash
./scripts/build_cli.sh
```

脚本会：

1. 清理本次构建相关的临时目录；
2. 使用当前 Python 环境构建 Wheel；
3. 检查 Wheel 中是否包含 `soinsight/cli/main.py`；
4. 检查 console entry point 是否为 `soinsight = soinsight.cli.main:main`；
5. 执行 `python3 -m soinsight --version` 冒烟测试。

默认产物：

```text
dist/soinsight-2.0.0.dev0-py3-none-any.whl
```

安装生成的 CLI：

```bash
python3 -m pip install --force-reinstall dist/soinsight-*.whl
soinsight --version
soinsight --help
```

也可以构建后直接安装到当前 Python 环境：

```bash
./scripts/build_cli.sh --install
```

指定 Python 或输出目录：

```bash
PYTHON_BIN=python3.10 ./scripts/build_cli.sh
DIST_DIR=/tmp/soinsight-dist ./scripts/build_cli.sh
```

不使用脚本时，等价的核心构建命令是：

```bash
python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

## 5. 验证 V2 框架

检查环境：

```bash
soinsight doctor
soinsight doctor --format json
```

查看已注册 Analyzer：

```bash
soinsight plugins list
soinsight plugins list --format json
```

当前内置 Analyzer 数量为 0 时会显示：

```text
No analyzers registered. Framework shell is ready.
```

执行框架扫描：

```bash
soinsight scan README.md
soinsight scan README.md --format json
```

当前会产生 `NO_ANALYZERS_SELECTED` warning，但命令本身成功。这可以验证以下链路已经工作：

```text
CLI → TargetResolver → Runtime → Aggregator → Renderer
```

## 6. 运行 V1

扫描单个 `.so`：

```bash
python3 main.py libexample.so
```

扫描目录：

```bash
python3 main.py ./lib/
```

查看参数：

```bash
python3 main.py --help
```

V1 的可选彩色输出依赖：

```bash
python3 -m pip install termcolor
```

缺少 `termcolor` 时仍可运行，只是输出不带颜色。

## 7. 常见安装问题

### `No module named soinsight`

尚未安装包时，应在仓库根目录运行：

```bash
PYTHONPATH=src python3 -m soinsight --help
```

或者执行：

```bash
python3 -m pip install -e .
```

### `readelf: not found`

安装 `binutils`，然后执行：

```bash
soinsight doctor
```

### V2 `elf` 返回 `ANALYSIS_PLAN_ERROR`

当前 `elf` 命令入口已经存在，但具体 `elf` Analyzer 尚未注册。这属于当前框架阶段的预期结果。
