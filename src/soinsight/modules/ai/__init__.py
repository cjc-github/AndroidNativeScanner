"""AI-assisted analysis capability domain."""

from ..model import CapabilityDefinition, ModuleDefinition

MODULE = ModuleDefinition(
    id="ai",
    name="AI 分析",
    description="基于已有证据进行可选的语义恢复、解释和辅助命名。",
    capabilities=(
        CapabilityDefinition("ai.function-name", "function-name", "函数命名", "根据调用、字符串和代码特征建议函数名。"),
        CapabilityDefinition("ai.parameter-semantics", "parameter-semantics", "参数语义恢复", "解释参数、返回值和调用约束。"),
        CapabilityDefinition("ai.struct-recovery", "struct-recovery", "结构体恢复", "辅助推断结构体字段及语义。"),
        CapabilityDefinition("ai.module-identification", "module-identification", "模块识别", "解释模块边界和职责。"),
        CapabilityDefinition("ai.algorithm-explanation", "algorithm-explanation", "算法解释", "解释算法识别证据和实现流程。"),
        CapabilityDefinition("ai.protocol-explanation", "protocol-explanation", "协议解释", "解释消息格式、状态和交互。"),
        CapabilityDefinition("ai.vulnerability-explanation", "vulnerability-explanation", "漏洞解释", "解释 Finding、证据、影响和修复建议。"),
        CapabilityDefinition("ai.assembly-explanation", "assembly-explanation", "汇编解释", "将局部汇编转换为结构化自然语言说明。"),
    ),
)

__all__ = ["MODULE"]
