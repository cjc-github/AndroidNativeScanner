# Android Native 库扫描工具 (.so 文件版) - 模块化版本

## 一、功能概述

本工具用于分析 Android 平台的原生动态链接库(.so 文件)，检测以下安全风险：

- 硬编码敏感信息 (令牌、API 密钥、JWT 等)
- 内嵌 URL 地址
- 危险函数调用 (`system`, `exec`等)
- JNI 方法名称暴露
- Base64 编码的负载数据

## 二、项目结构

新的模块化结构将功能拆分为多个独立的文件：

```
AndroidNativeScanner/
├── main.py                 # 主程序入口
├── native_scanner.py       # 原始单文件版本（保留）
├── src/                    # 模块化代码目录
│   ├── __init__.py         # 包初始化文件
│   ├── config.py           # 配置和常量定义
│   ├── utils.py            # 通用工具函数
│   ├── scanners.py         # 检测和扫描辅助函数
│   ├── analyzer.py         # 单文件分析主逻辑
│   └── cli.py              # 命令行解析和入口逻辑
└── README.md               # 项目说明
```

## 三、使用方式

安装依赖：

```bash
pip install termcolor
```

### 3.1 使用新模块化版本（推荐）

扫描单个文件：
```bash
python3 main.py libexample.so
```

批量扫描目录：
```bash
python3 main.py ./lib/
```

### 3.2 使用原始单文件版本

扫描单个文件：
```bash
python3 native_scanner.py libexample.so
```

批量扫描目录：
```bash
python3 native_scanner.py ./lib/
```

## 四、模块说明

### config.py
- 包含所有正则模式、关键词、工具依赖等配置信息
- 预编译正则表达式以提高性能

### utils.py
- 外部命令执行工具函数
- 文件操作和路径处理函数

### scanners.py
- 各种字符串检测和扫描功能
- Base64 解码、敏感模式匹配、URL 检测等

### analyzer.py
- 单个 .so 文件的分析逻辑
- 风险评分和报告生成

### cli.py
- 命令行参数解析
- 主程序入口逻辑

## 五、输出结果

- 终端实时显示扫描报告
- 自动生成 `report_*.txt`日志文件 (包含完整扫描结果)

## 六、技术实现

- **模块化设计**：功能分离，便于维护和扩展
- **二进制分析**：通过反汇编引擎解析 ELF 文件结构
- **模式匹配**：使用正则表达式识别敏感数据模式
- **交叉引用**：追踪危险函数的调用链
- **字符串提取**：分析可打印字符的上下文关系