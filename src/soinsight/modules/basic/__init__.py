"""Basic analysis capability domain."""

from ..model import CapabilityDefinition, ModuleDefinition

MODULE = ModuleDefinition(
    id="basic",
    name="基础分析",
    description="建立二进制、ELF、代码结构和统一 IR 的基础事实。",
    capabilities=(
        CapabilityDefinition("basic.file", "file", "文件分析", "文件属性、指纹、Magic 与基础识别。"),
        CapabilityDefinition("basic.elf", "elf", "ELF 解析", "ELF Header、Section、Segment、Dynamic 等。"),
        CapabilityDefinition("basic.symbols", "symbols", "Symbol 解析", "导入、导出、版本化符号与符号关系。"),
        CapabilityDefinition("basic.dwarf", "dwarf", "DWARF 解析", "调试信息、源码位置、类型和变量信息。"),
        CapabilityDefinition("basic.types", "types", "类型恢复", "函数签名、变量和复合类型恢复。"),
        CapabilityDefinition("basic.cpp", "cpp", "C++ 恢复", "RTTI、vtable、继承和构造析构关系。"),
        CapabilityDefinition("basic.disasm", "disasm", "反汇编", "指令、函数边界和代码区域恢复。"),
        CapabilityDefinition("basic.cfg", "cfg", "CFG 恢复", "基本块、边和控制流结构恢复。"),
        CapabilityDefinition("basic.callgraph", "callgraph", "Call Graph 恢复", "Caller/Callee 与跨函数调用关系。"),
        CapabilityDefinition("basic.dataflow", "dataflow", "Data Flow 分析", "Use-Def、数据依赖和基础传播关系。"),
    ),
)

__all__ = ["MODULE"]
