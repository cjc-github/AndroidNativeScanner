"""ELF parsing and symbol-name interpretation infrastructure.

This package gives built-in analyzers dependency-free access to ELF facts:
section and symbol tables are decoded directly, and C++ / JNI symbol names are
interpreted without external toolchains such as ``readelf``, ``nm`` or
``c++filt``.
"""

from .demangle import DemangledSymbol, demangle
from .dynamic import parse_dynamic_info
from .jni import JniSymbol, decode_jni_symbol
from .parser import ElfFile, ElfFormatError, parse_bytes, parse_elf
from .relocations import parse_relocations, relocation_type_name
from .structures import (
    DynamicEntry,
    DynamicInfo,
    ElfHeader,
    ProgramHeader,
    Relocation,
    SectionHeader,
    Symbol,
    SymbolVersion,
    VersionDefinition,
    VersionRequirement,
)

__all__ = [
    "DemangledSymbol",
    "DynamicEntry",
    "DynamicInfo",
    "ElfFile",
    "ElfFormatError",
    "ElfHeader",
    "JniSymbol",
    "ProgramHeader",
    "Relocation",
    "SectionHeader",
    "Symbol",
    "SymbolVersion",
    "VersionDefinition",
    "VersionRequirement",
    "decode_jni_symbol",
    "demangle",
    "parse_bytes",
    "parse_dynamic_info",
    "parse_elf",
    "parse_relocations",
    "relocation_type_name",
]
