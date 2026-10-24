"""Immutable value objects for parsed ELF structures."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ElfHeader:
    """Decoded ``Elf*_Ehdr`` fields with enum names resolved."""

    elf_class: str
    endianness: str
    os_abi: str
    abi_version: int
    type: str
    machine: str
    entry_point: int
    program_header_offset: int
    section_header_offset: int
    flags: int
    header_size: int
    program_header_entry_size: int
    program_header_count: int
    section_header_entry_size: int
    section_header_count: int
    section_name_table_index: int

    @property
    def is_64bit(self) -> bool:
        return self.elf_class == "ELF64"


@dataclass(frozen=True)
class ProgramHeader:
    """Decoded ``Elf*_Phdr`` fields."""

    type: str
    flags: int
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    alignment: int

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & 0x1)


@dataclass(frozen=True)
class SectionHeader:
    """Decoded ``Elf*_Shdr`` fields with the section name resolved."""

    index: int
    name: str
    type: str
    type_value: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class Symbol:
    """Decoded ``Elf*_Sym`` entry with resolved name, bind, type and visibility."""

    name: str
    bind: str
    type: str
    type_value: int
    visibility: str
    section_index: int
    value: int
    size: int
    table: str

    @property
    def is_function(self) -> bool:
        return self.type_value in (2, 10)  # STT_FUNC, STT_GNU_IFUNC

    @property
    def is_defined(self) -> bool:
        return self.section_index != 0  # SHN_UNDEF marks an import

    @property
    def is_exported(self) -> bool:
        """True for dynamic symbols visible to linkers and dlopen/dlsym."""
        return self.is_defined and self.bind in ("GLOBAL", "WEAK")
