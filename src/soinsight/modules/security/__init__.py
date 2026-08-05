"""Security analysis capability domain."""

from ..model import CapabilityDefinition, ModuleDefinition

MODULE = ModuleDefinition(
    id="security",
    name="安全分析",
    description="基于静态、语义和运行时证据形成安全 Finding 与风险结论。",
    capabilities=(
        CapabilityDefinition("security.hardening", "hardening", "安全保护检测", "NX、RELRO、PIE、Canary、CFI、PAC 等。"),
        CapabilityDefinition("security.dangerous-api", "dangerous-api", "危险 API 检测", "危险导入、调用点和上下文证据。"),
        CapabilityDefinition("security.vulnerability", "vulnerability", "漏洞模式识别", "基于规则、图和数据流的漏洞候选识别。"),
        CapabilityDefinition("security.risk", "risk", "风险评估", "Finding 去重、严重度、置信度和风险汇总。"),
    ),
)

__all__ = ["MODULE"]
