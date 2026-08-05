"""Dynamic analysis capability domain."""

from ..model import CapabilityDefinition, ModuleDefinition

MODULE = ModuleDefinition(
    id="dynamic",
    name="动态分析",
    description="在显式授权和隔离环境中采集运行时行为证据。",
    capabilities=(
        CapabilityDefinition("dynamic.trace", "trace", "Runtime Trace", "函数、模块和事件运行轨迹。"),
        CapabilityDefinition("dynamic.arguments", "arguments", "参数采集", "调用参数、返回值和上下文采集。"),
        CapabilityDefinition("dynamic.memory", "memory", "内存分析", "内存映射、访问和关键数据观测。"),
        CapabilityDefinition("dynamic.syscalls", "syscalls", "系统调用分析", "系统调用及文件、网络和进程行为。"),
        CapabilityDefinition("dynamic.coverage", "coverage", "覆盖率分析", "函数、基本块和边覆盖率。"),
    ),
)

__all__ = ["MODULE"]
