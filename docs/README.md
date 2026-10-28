# SOInsight 文档中心

## 使用者文档

1. [快速使用](quickstart.md) —— 安装、最常用命令、输出与配置速览（一页，日常看这份就够）
2. [模块体系](module-system.md) —— 六大产品模块、42 项能力及跨域依赖规则
3. [项目状态与路线图](project-status.md) —— 已完成、未实现和下一阶段验收标准
4. [未完成分析能力与技术债](pending-capabilities.md) —— 只有外壳或尚未落地能力的逐项分析
5. [详细使用文档归档](archive/) —— 原快速开始/使用手册/CLI 命令参考/YAML 配置指南（完整参数与字段说明）

## 开发者文档

1. [架构说明](architecture.md)
2. [扩展开发指南](extension-development.md)
3. [V1 到 V2 迁移](migration-v1-to-v2.md)
4. [V2 软件设计说明书](../design/design_v2.0.md)
5. [V3 设计占位与启动条件](../design/design_v3.0.md)
6. [V1 历史规划](../design/design_v1.0.md)

## 阅读顺序

- 要使用 CLI：先看[快速使用](quickstart.md)；需要完整参数时再查 `archive/` 下对应文档；
- 要理解产品边界：V2 软件设计说明书 → 模块体系 → 架构说明；
- 要实现新能力：架构说明 → 扩展开发指南 → 迁移指南；
- 要判断“目前能不能用”：项目状态与路线图。

## 文档约定

- **模块**默认指基础、高级、安全、动态、AI、自动化六个产品能力域；
- **Analyzer/Rule/Renderer/Scheduler**指内部技术扩展点，不与产品模块同义；
- “已实现”表示代码和测试可验证；“命令外壳”不代表具体分析能力已经完成；
- 未安装包时使用 `PYTHONPATH=src python3 -m soinsight`，安装后可直接使用 `soinsight`；
- `docs/archive/` 为历史详细文档，如与最新行为有出入，以快速使用、模块体系和代码为准。
