# Android Native 库扫描工具 (.so 文件版) - 重构版本

## 一、功能概述

本工具用于分析 Android 平台的原生动态链接库(.so 文件)，检测以下安全风险：

- 硬编码敏感信息 (令牌、API 密钥、JWT 等)
- 内嵌 URL 地址
- 危险函数调用 (`system`, `exec`等)
- JNI 方法名称暴露
- Base64 编码的负载数据

## 二、项目结构

重构后的模块化结构采用配置分散设计，每个分析器包含自己的配置：

```
AndroidNativeScanner/
├── main.py                 # 主程序入口
├── reports/                # 扫描报告目录
│   ├── report_*.txt       # 生成的扫描报告
├── src/                    # 模块化代码目录
│   ├── __init__.py         # 包初始化文件
│   ├── cli.py              # 命令行解析和入口逻辑
│   ├── scanners.py         # 检测和扫描辅助函数
│   ├── utils.py            # 通用工具函数
│   └── analyzer/           # 分析器模块目录
│       ├── __init__.py     # 分析器包初始化
│       ├── analysis_coordinator.py  # 分析协调器
│       ├── elf_analyzer.py          # ELF 头信息分析
│       ├── symbol_analyzer.py       # 符号分析（包含 RCE 关键词）
│       ├── string_analyzer.py       # 字符串提取分析
│       ├── sensitive_analyzer.py    # 敏感模式检测（包含敏感模式配置）
│       ├── url_analyzer.py          # URL 检测（包含 URL 正则配置）
│       ├── base64_analyzer.py       # Base64 编码检测（包含 Base64 配置）
│       └── jni_analyzer.py          # JNI 方法分析（包含 JNI 关键词）
└── README.md               # 项目说明
```

## 三、使用方式

安装依赖：

```bash
pip install termcolor
```

### 3.1 扫描单个文件
```bash
python3 main.py libexample.so
```

### 3.2 批量扫描目录
```bash
python3 main.py ./lib/
```

### 3.3 静默模式（仅输出结果）
```bash
python3 main.py libexample.so -q
```

## 四、模块说明

### 4.1 分析器模块 (analyzer/)
采用配置分散设计，每个分析器包含自己的配置：

- **elf_analyzer.py**: ELF 头信息分析
- **symbol_analyzer.py**: 符号分析，包含 RCE 关键词配置
- **string_analyzer.py**: 字符串提取和基础分析
- **sensitive_analyzer.py**: 敏感模式检测，包含敏感模式正则配置
- **url_analyzer.py**: URL 检测，包含 URL 正则配置
- **base64_analyzer.py**: Base64 编码检测，包含 Base64 配置
- **jni_analyzer.py**: JNI 方法分析，包含 JNI 关键词配置
- **analysis_coordinator.py**: 分析协调器，管理各分析器执行顺序

### 4.2 核心模块
- **scanners.py**: 各种字符串检测和扫描功能
- **config.py**: 重构后仅保留工具依赖配置
- **utils.py**: 外部命令执行和文件操作工具函数
- **cli.py**: 命令行参数解析和主程序入口逻辑

## 五、重构特点

### 5.1 配置分散架构
- 每个分析器模块包含自己的配置，职责清晰
- 消除了循环依赖问题
- 便于独立测试和维护

### 5.2 风险评分系统
- **ELF 头分析**: 基础风险分数
- **符号分析**: 每个危险符号 5 分
- **敏感模式检测**: Key/Token 类型 4 分，JWT 类型 3 分，其他 2 分
- **URL 检测**: 每个 URL 2 分
- **Base64 检测**: 每个 Base64 字符串 3 分
- **JNI 分析**: 每个 JNI 方法 2 分

### 5.3 风险等级划分
- **LOW**: 0-20 分
- **MEDIUM**: 21-40 分
- **HIGH**: 41-60 分
- **CRITICAL**: 61+ 分

## 六、输出结果

- 终端实时显示扫描进度和风险报告
- 自动生成 `report_*.txt` 日志文件（包含完整扫描结果）
- 详细的风险分数分布和检测详情

## 七、技术实现

- **模块化设计**: 配置分散，功能分离，便于维护和扩展
- **二进制分析**: 通过反汇编引擎解析 ELF 文件结构
- **模式匹配**: 使用正则表达式识别敏感数据模式
- **交叉引用**: 追踪危险函数的调用链
- **字符串提取**: 分析可打印字符的上下文关系