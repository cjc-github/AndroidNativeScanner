"""Automation capability domain."""

from ..model import CapabilityDefinition, ModuleDefinition

MODULE = ModuleDefinition(
    id="automation",
    name="自动化",
    description="将分析能力组合为可复现的 Diff、Fuzz、报告和 CI 工作流。",
    capabilities=(
        CapabilityDefinition(
            "automation.binary-diff", "binary-diff", "Binary Diff", "二进制、函数、图和 Finding 差异。", ("old", "new")
        ),
        CapabilityDefinition("automation.fuzz-target", "fuzz-target", "Fuzz Target 识别", "识别可测试入口和约束。"),
        CapabilityDefinition("automation.harness", "harness", "Harness 生成", "生成或辅助生成 Fuzz Harness。"),
        CapabilityDefinition("automation.seed", "seed", "Seed 生成", "根据格式、协议和常量生成种子。"),
        CapabilityDefinition("automation.crash-cluster", "crash-cluster", "Crash 聚类", "按栈、信号和根因线索聚类。"),
        CapabilityDefinition("automation.report", "report", "报告自动化", "统一结果转换、归档和发布。"),
        CapabilityDefinition("automation.workflow", "workflow", "工作流自动化", "批处理、Profile、CI Gate 和流水线编排。"),
    ),
)

__all__ = ["MODULE"]
