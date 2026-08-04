# SOInsight ------ 面向 Linux/Android ELF 动态库的深度分析平台（Plan V1.0）

## 1. 项目目标

构建一个支持 Linux/Android ELF 动态库（`.so`）的自动化分析平台，实现： -
ELF 信息解析 - 符号恢复 - 类型恢复 - C++ 类恢复 - CFG / Call Graph
恢复 - 数据流分析 - 算法识别 - 第三方库识别 - 安全分析 - AI 语义分析 -
Fuzz Harness 自动生成 - JSON / HTML / PDF 报告输出

## 2. 总体架构

``` text
CLI/Web UI
    │
Analysis Scheduler
    │
├── File Parser
├── ELF Parser
├── Symbol Engine
├── Type Recovery
├── Disassembler
├── CFG Engine
├── CallGraph Engine
├── DataFlow Engine
├── Security Engine
├── AI Engine
└── Report Engine
```

## 3. 分析流程

SO → 文件分析 → ELF解析 → 符号解析 → 类型恢复 → 反汇编 → CFG → CallGraph
→ DataFlow → 算法识别 → 安全分析 → AI语义分析 → 报告

## 4. 功能模块

### 4.1 文件分析

-   Hash、Entropy、Magic、Architecture、ABI、BuildID、Strip状态

### 4.2 ELF解析

-   Header、Section、Segment、Dynamic、Relocation、TLS、Version

### 4.3 Symbol分析

-   导入/导出符号、Weak/Hidden/Local/Global/TLS Symbol

### 4.4 DWARF解析

-   源文件、变量、参数、结构体、类、模板、命名空间

### 4.5 C++恢复

-   RTTI、vtable、继承关系、构造/析构函数、虚函数

### 4.6 反汇编

-   Instruction、IR、BasicBlock

### 4.7 CFG

-   BasicBlock、Loop、Switch、Exception、Dominator

### 4.8 CallGraph

-   Caller/Callee、递归、热点函数

### 4.9 类型恢复

-   Struct、Class、Union、Enum、Pointer、Template

### 4.10 DataFlow

-   Use-Def、Alias、Pointer Flow、对象生命周期

### 4.11 常量分析

-   AES、CRC、MD5、SHA、SM2/3/4、Magic Number、UUID

### 4.12 字符串分析

-   URL、IP、JSON、XML、SQL、日志、配置、路径

### 4.13 算法识别

-   加密、哈希、压缩、编码、序列化算法

### 4.14 第三方库识别

-   OpenSSL、Boost、Qt、SQLite、protobuf、gRPC、FFmpeg 等

### 4.15 安全分析

-   RELRO、NX、PIE、Canary、FORTIFY、CFI、PAC
-   危险API、漏洞模式检测

### 4.16 动态分析

-   GDB、Frida、QBDI、DynamoRIO、PIN
-   参数、覆盖率、运行时CFG、内存行为

### 4.17 AI分析

-   函数命名
-   参数语义恢复
-   结构体恢复
-   模块职责识别
-   漏洞解释
-   自动注释
-   Harness生成

### 4.18 Report

-   JSON、HTML、Markdown、PDF、GraphML、GEXF

## 5. 建议新增模块

### Binary Diff

-   两个SO版本差异分析
-   CFG变化
-   函数变化
-   Patch分析

### Fuzz Analysis

-   Target识别
-   参数约束恢复
-   Harness生成
-   Crash分析
-   Seed管理

## 6. 统一IR

Binary → Module → Function → BasicBlock → Instruction → Operand

Type → Class → Struct → Field

Resource → String → Constant → Algorithm → Library → Protocol

## 7. Roadmap

1.  ELF基础解析
2.  CFG/CallGraph
3.  类型恢复
4.  数据流
5.  安全分析
6.  AI分析
7.  动态分析
8.  Fuzz自动化
