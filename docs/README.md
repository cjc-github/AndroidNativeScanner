# SOInsight 文档中心

本文档目录面向 SOInsight V2 的使用者和开发者。V2 目前处于框架阶段，文档会明确区分“已经实现”和“规划能力”。

## 使用者文档

1. [快速开始](getting-started.md)
2. [V2 使用手册](user-guide.md)
3. [CLI 命令参考](cli-reference.md)
4. [项目状态与路线图](project-status.md)

## 开发者文档

1. [V2 架构说明](architecture.md)
2. [Analyzer 与 Rule 开发指南](extension-development.md)
3. [V1 到 V2 迁移指南](migration-v1-to-v2.md)
4. [V2 总体设计](../design/SOInsight_V2.0_Software_Design_Specification.md)

## 文档约定

- **已实现**：当前仓库中存在实现，并经过测试或命令验证；
- **框架接口**：接口或占位命令已经存在，但没有实际业务能力；
- **规划**：设计目标，不应被理解为当前 CLI 已经支持；
- 示例默认从仓库根目录执行；
- 未安装包时，命令使用 `PYTHONPATH=src python3 -m soinsight`；
- 可编辑安装后，可以直接使用 `soinsight`。
