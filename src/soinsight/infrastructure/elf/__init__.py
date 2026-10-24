"""ELF parsing and symbol-name interpretation infrastructure.

This package gives built-in analyzers dependency-free access to ELF facts:
section and symbol tables are decoded directly, and C++ / JNI symbol names are
interpreted without external toolchains such as ``readelf``, ``nm`` or
``c++filt``.
"""

from .demangle import DemangledSymbol, demangle
from .jni import JniSymbol, decode_jni_symbol
from .parser import ElfFile, ElfFormatError, parse_bytes, parse_elf
from .structures import ElfHeader, ProgramHeader, SectionHeader, Symbol

__all__ = [
    "DemangledSymbol",
    "ElfFile",
    "ElfFormatError",
    "ElfHeader",
    "JniSymbol",
    "ProgramHeader",
    "SectionHeader",
    "Symbol",
    "decode_jni_symbol",
    "demangle",
    "parse_bytes",
    "parse_elf",
]
