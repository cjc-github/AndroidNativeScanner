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


@dataclass(frozen=True)
class DynamicEntry:
    """One decoded ``Elf*_Dyn`` entry from the ``.dynamic`` table."""

    tag: str
    tag_value: int
    value: int


@dataclass(frozen=True)
class VersionDefinition:
    """One version an image defines itself (``Elf*_Verdef``)."""

    index: int
    name: str
    is_base: bool


@dataclass(frozen=True)
class VersionRequirement:
    """One version an image demands of a dependency (``Elf*_Verneed``)."""

    name: str
    file: str
    index: int
    flags: int


@dataclass(frozen=True)
class SymbolVersion:
    """The version a dynamic symbol belongs to."""

    name: str
    index: int
    hidden: bool


@dataclass(frozen=True)
class Relocation:
    """One load-time relocation applied to the image."""

    section: str
    offset: int
    symbol_index: int
    symbol_name: str | None
    type: int
    addend: int
    kind: str  # rela | rel


@dataclass(frozen=True)
class DynamicInfo:
    """The dynamic-linking facts an image declares about itself.

    ``needed`` lists the shared objects the loader must provide, ``init_array``
    and ``fini_array`` hold the constructors and destructors that run around
    ``main``, and the search path entries decide which library wins when two
    provide the same soname.
    """

    entries: tuple[DynamicEntry, ...] = ()
    needed: tuple[str, ...] = ()
    soname: str | None = None
    rpath: str | None = None
    runpath: str | None = None
    init: int | None = None
    fini: int | None = None
    init_array: tuple[int, ...] = ()
    fini_array: tuple[int, ...] = ()
    preinit_array: tuple[int, ...] = ()
    flags: int = 0
    flags_1: int = 0
    bind_now: bool = False
    has_textrel: bool = False
    version_definitions: tuple[VersionDefinition, ...] = ()
    version_requirements: tuple[VersionRequirement, ...] = ()
    symbol_versions: tuple[SymbolVersion, ...] = ()
