"""ELF format constants.

Values follow the ELF specification (Tool Interface Standards, ELF format
specification version 1.2) and the GNU extensions used by Android NDK builds.
"""

ELF_MAGIC = b"\x7fELF"

EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFCLASS_NAMES = {ELFCLASS32: "ELF32", ELFCLASS64: "ELF64"}

ELFDATA2LSB = 1
ELFDATA2MSB = 2
ENDIANNESS_NAMES = {ELFDATA2LSB: "little", ELFDATA2MSB: "big"}

EV_CURRENT = 1

# e_type
ET_NAMES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

# e_machine
EM_NAMES = {
    0: "None",
    2: "SPARC",
    3: "x86",
    4: "68K",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    22: "S390",
    40: "ARM",
    42: "SuperH",
    43: "SPARCv9",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

# EI_OSABI
OSABI_NAMES = {
    0: "SYSV",
    1: "HPUX",
    2: "NetBSD",
    3: "Linux",
    6: "Solaris",
    7: "AIX",
    8: "IRIX",
    9: "FreeBSD",
    10: "Tru64",
    11: "Novell Modesto",
    12: "OpenBSD",
    64: "ARM EABI",
    97: "ARM",
    255: "Standalone",
}

# Section header types
SHT_NAMES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
    0x6FFFFFF5: "GNU_ATTRIBUTES",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFF7: "GNU_LIBLIST",
    0x6FFFFFFD: "GNU_VERDEF",
    0x6FFFFFFE: "GNU_VERNEED",
    0x6FFFFFFF: "GNU_VERSYM",
}

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Symbol bindings
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_GNU_UNIQUE = 10
STB_NAMES = {
    STB_LOCAL: "LOCAL",
    STB_GLOBAL: "GLOBAL",
    STB_WEAK: "WEAK",
    STB_GNU_UNIQUE: "GNU_UNIQUE",
}

# Symbol types
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_GNU_IFUNC = 10
STT_NAMES = {
    STT_NOTYPE: "NOTYPE",
    STT_OBJECT: "OBJECT",
    STT_FUNC: "FUNC",
    STT_SECTION: "SECTION",
    STT_FILE: "FILE",
    STT_COMMON: "COMMON",
    STT_TLS: "TLS",
    STT_GNU_IFUNC: "GNU_IFUNC",
}

# Symbol visibility
STV_DEFAULT = 0
STV_INTERNAL = 1
STV_HIDDEN = 2
STV_PROTECTED = 3
STV_NAMES = {
    STV_DEFAULT: "DEFAULT",
    STV_INTERNAL: "INTERNAL",
    STV_HIDDEN: "HIDDEN",
    STV_PROTECTED: "PROTECTED",
}

# Special section header indices
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_HIRESERVE = 0xFFFF
SHN_XINDEX = 0xFFFF

# Program header types
PT_NAMES = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
    0x6474E550: "GNU_EH_FRAME",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
    0x6474E553: "GNU_PROPERTY",
    0x6474E554: "GNU_SFRAME",
}

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

# Well-known section names
SECTION_DYNSYM = ".dynsym"
SECTION_SYMTAB = ".symtab"
SECTION_SHSTRTAB = ".shstrtab"

# GNU property note (PT_GNU_PROPERTY / .note.gnu.property) constants used to
# expose AArch64 Branch Target Identification and Pointer Authentication.
# Values follow the generic ELF gABI plus the AArch64 ELF ABI addendum.
PT_GNU_PROPERTY = 0x6474E553
SECTION_NOTE_GNU_PROPERTY = ".note.gnu.property"

# Property types inside a GNU_PROPERTY_TYPE_0 descriptor.
GNU_PROPERTY_TYPE_0 = 0
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000

# Feature bits of GNU_PROPERTY_AARCH64_FEATURE_1_AND.
GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 0x01
GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 0x02

SHT_NOTE = 7
