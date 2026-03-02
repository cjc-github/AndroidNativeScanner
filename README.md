# Android Native 库扫描工具 (.so 文件分析器)

## 一、功能概述

本工具用于分析 Android 平台的原生动态链接库（.so 文件），检测以下安全风险：

- 硬编码敏感信息（API Key、Token、JWT 等）
- 内嵌 URL 地址
- 危险函数调用（`system`、`exec`、`popen` 等）
- JNI 方法名称暴露
- Base64 编码的负载数据
- ELF 头结构信息

## 二、项目结构

采用 **BaseAnalyzer 抽象基类 + 协调器** 的架构，每个分析器完全自包含，既可独立使用，也可由协调器统一调度：

```
AndroidNativeScanner/
├── main.py                          # 主程序入口
├── README.md                        # 项目说明
├── reports/                         # 扫描报告输出目录
│   └── report_*.txt
└── src/                             # 源码目录
    ├── __init__.py                  # 包初始化
    ├── cli.py                       # 命令行解析与主流程
    ├── utils.py                     # 通用工具函数
    └── analyzer/                    # 分析器模块
        ├── __init__.py              # 统一导出
        ├── base.py                  # BaseAnalyzer 抽象基类
        ├── analysis_coordinator.py  # 分析协调器
        ├── elf_analyzer.py          # ELF 头信息分析
        ├── symbol_analyzer.py       # 导出符号 & RCE 危险函数检测
        ├── string_analyzer.py       # 字符串提取与统计
        ├── sensitive_analyzer.py    # 敏感信息模式检测
        ├── url_analyzer.py          # 硬编码 URL 检测
        ├── base64_analyzer.py       # Base64 编码数据检测
        └── jni_analyzer.py          # JNI 符号分析
```

## 三、架构设计

### 3.1 BaseAnalyzer 抽象基类

所有分析器继承自 `BaseAnalyzer`，实现统一接口：

```python
class BaseAnalyzer(ABC):
    name: str       # 分析器显示名称
    key: str        # 结果字典中的键名
    summary_key: str  # 摘要字典中的键名

    def analyze(self, so_file: str, **context) -> Any:
        """对 .so 文件执行分析"""

    def summarize(self, results: Any) -> Dict[str, Any]:
        """生成包含 risk_score 的摘要"""
```

### 3.2 独立使用单个分析器

每个分析器可以脱离协调器独立运行：

```python
from src.analyzer import UrlAnalyzer

analyzer = UrlAnalyzer()
urls = analyzer.analyze("libexample.so")
summary = analyzer.summarize(urls)
print(f"发现 {summary['total_urls']} 个 URL，风险分: {summary['risk_score']}")
```

### 3.3 协调器统一调度

`AnalysisCoordinator` 按顺序执行所有分析器，自动共享字符串提取结果以避免重复调用：

```python
from src.analyzer import AnalysisCoordinator

coordinator = AnalysisCoordinator()
results = coordinator.analyze("libexample.so")
summary = coordinator.summarize(results)
```

## 四、使用方式

### 4.1 安装依赖

```bash
pip install termcolor
```

系统需要安装 `readelf`、`nm`、`strings` 工具（通常包含在 `binutils` 包中）。

### 4.2 扫描单个文件

```bash
python3 main.py libexample.so
```

### 4.3 批量扫描目录

```bash
python3 main.py ./lib/
```

### 4.4 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `path` | .so 文件或目录路径 | (必填) |
| `-o`, `--out` | 报告输出目录 | `reports` |
| `-j`, `--jobs` | 并行 worker 数 | `4` |
| `-t`, `--timeout` | 外部工具超时（秒） | `20` |
| `-q`, `--quiet` | 静默模式 | 否 |

## 五、分析器说明

| 分析器 | 类名 | 功能 | 风险计分 |
|--------|------|------|----------|
| ELF 头分析 | `ElfAnalyzer` | 解析 ELF 头信息（类型、架构、入口点等） | 固定 0 分 |
| 符号分析 | `SymbolAnalyzer` | 检测导出符号中的 RCE 相关危险函数 | 每个危险符号 5 分（上限 30） |
| 字符串分析 | `StringAnalyzer` | 提取可打印字符串并统计 | 每 100 个字符串 1 分 |
| 敏感模式 | `SensitiveAnalyzer` | 检测 API Key、Token、JWT 等 | Key/Token 4 分，JWT 3 分，其他 2 分 |
| URL 检测 | `UrlAnalyzer` | 检测硬编码 URL | 每个 URL 2 分 |
| Base64 检测 | `Base64Analyzer` | 检测 Base64 编码数据 | 每个 3 分 |
| JNI 分析 | `JniAnalyzer` | 检测 JNI 相关符号和方法 | 每个 JNI 符号 2 分 |

## 六、风险等级划分

| 等级 | 分数范围 | 说明 |
|------|----------|------|
| LOW | 0–19 | 风险较低 |
| MEDIUM | 20–39 | 存在一定风险 |
| HIGH | 40–59 | 存在较高风险 |
| CRITICAL | 60+ | 存在严重风险 |

## 七、输出结果

- 终端实时显示各分析器的扫描进度
- 自动生成 `reports/report_*.txt` 报告文件（包含完整 JSON 结果）
- 报告包含：风险等级、总风险分、各模块风险分明细、详细检测结果

## 八、扩展开发

新增分析器只需三步：

1. 在 `src/analyzer/` 下创建新文件，继承 `BaseAnalyzer`
2. 实现 `analyze()` 和 `summarize()` 方法
3. 在 `AnalysisCoordinator.__init__()` 中注册新分析器实例

```python
from .base import BaseAnalyzer

class MyAnalyzer(BaseAnalyzer):
    name = "自定义分析"
    key = "my_analysis"
    summary_key = "my_summary"

    def analyze(self, so_file, **context):
        # 实现分析逻辑
        ...

    def summarize(self, results):
        return {"risk_score": 0, ...}
```
