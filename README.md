# Android Native 库扫描工具 (.so 文件版)

## 一、功能概述

本工具用于分析 Android 平台的原生动态链接库(.so 文件)，检测以下安全风险：

- 硬编码敏感信息 (令牌、API 密钥、JWT 等)

- 内嵌 URL 地址

- 危险函数调用 (`system`, `exec`等)

- JNI 方法名称暴露

- Base64 编码的负载数据

## 二、使用方式

安装termcolor

```bash
pip install termcolor
```

### 2.1 扫描单个文件

```
python3 native_scanner.py libexample.so
```

### 2.2 批量扫描目录

```
python3 native_scanner.py ./lib/
```

## 三、输出结果

- 终端实时显示扫描报告

- 自动生成 `report_*.txt`日志文件 (包含完整扫描结果)

## 四、技术实现

- **二进制分析**：通过反汇编引擎解析 ELF 文件结构
- **模式匹配**：使用正则表达式识别敏感数据模式
- **交叉引用**：追踪危险函数的调用链
- **字符串提取**：分析可打印字符的上下文关系

