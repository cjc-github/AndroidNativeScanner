"""Advanced analysis capability domain."""

from ..model import CapabilityDefinition, ModuleDefinition

MODULE = ModuleDefinition(
    id="advanced",
    name="高级分析",
    description="在基础事实之上完成语义、特征和来源识别。",
    capabilities=(
        CapabilityDefinition("advanced.strings", "strings", "字符串分析", "字符串提取、分类、引用和语义线索。"),
        CapabilityDefinition("advanced.constants", "constants", "常量分析", "常量、Magic Number 和特征值分析。"),
        CapabilityDefinition("advanced.algorithm", "algorithm", "算法识别", "加密、哈希、压缩、编码等算法识别。"),
        CapabilityDefinition("advanced.protocol", "protocol", "协议识别", "网络和私有协议特征识别。"),
        CapabilityDefinition("advanced.file-format", "file-format", "文件格式识别", "资源、容器和内嵌文件格式识别。"),
        CapabilityDefinition("advanced.library", "library", "第三方库识别", "组件、依赖库和版本线索识别。"),
        CapabilityDefinition("advanced.compiler", "compiler", "编译器识别", "编译器、工具链和编译选项特征。"),
        CapabilityDefinition("advanced.obfuscation", "obfuscation", "混淆识别", "控制流、符号、字符串和打包混淆特征。"),
    ),
)

__all__ = ["MODULE"]
