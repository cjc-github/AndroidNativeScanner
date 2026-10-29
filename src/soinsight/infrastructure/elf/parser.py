"""Pure-Python ELF image parser.

Built-in analyzers must work without an external toolchain (readelf, nm and
objdump are absent on many developer machines), so section and symbol tables
are decoded directly with :mod:`struct`.

Every read is bounds-checked: a malformed or truncated image raises
:class:`ElfFormatError` instead of surfacing as a raw ``struct.error`` or
``UnicodeDecodeError`` from an analyzer. Missing optional structures (no
program headers, no symbol table) are not errors; callers must treat absent
facts as unknown rather than as a negative answer.
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Union

from . import constants as elf
from .dynamic import parse_dynamic_info
from .relocations import parse_relocations
from .structures import (
    DynamicInfo,
    ElfHeader,
    ProgramHeader,
    Relocation,
    SectionHeader,
    Symbol,
)


class ElfFormatError(ValueError):
    """The target bytes are not a parseable ELF image."""


_BytesLike = Union[bytes, bytearray, memoryview, mmap.mmap]

_ELF32_HEADER_FIELDS = "HHIIIIIHHHHHH"
_ELF64_HEADER_FIELDS = "HHIQQQIHHHHHH"
_ELF32_PHDR_FIELDS = "IIIIIIII"
_ELF64_PHDR_FIELDS = "IIQQQQQQ"
_ELF32_SHDR_FIELDS = "IIIIIIIIII"
_ELF64_SHDR_FIELDS = "IIQQQQIIQQ"
_ELF32_SYM_FIELDS = "IIIBBH"
_ELF64_SYM_FIELDS = "IBBHQQ"

_ELF32_HEADER_SIZE = struct.calcsize("<" + _ELF32_HEADER_FIELDS) + 16
_ELF64_HEADER_SIZE = struct.calcsize("<" + _ELF64_HEADER_FIELDS) + 16
_ELF32_PHDR_SIZE = struct.calcsize("<" + _ELF32_PHDR_FIELDS)
_ELF64_PHDR_SIZE = struct.calcsize("<" + _ELF64_PHDR_FIELDS)
_ELF32_SHDR_SIZE = struct.calcsize("<" + _ELF32_SHDR_FIELDS)
_ELF64_SHDR_SIZE = struct.calcsize("<" + _ELF64_SHDR_FIELDS)
_ELF32_SYM_SIZE = struct.calcsize("<" + _ELF32_SYM_FIELDS)
_ELF64_SYM_SIZE = struct.calcsize("<" + _ELF64_SYM_FIELDS)


@dataclass(frozen=True)
class ElfFile:
    """A parsed ELF image: header, program headers, sections and symbols."""

    header: ElfHeader
    program_headers: tuple[ProgramHeader, ...]
    sections: tuple[SectionHeader, ...]
    symbols: tuple[Symbol, ...]
    aarch64_feature_1: int | None = None
    dynamic: DynamicInfo = DynamicInfo()
    relocations: tuple[Relocation, ...] = ()

    @property
    def is_64bit(self) -> bool:
        return self.header.elf_class == "ELF64"

    def section(self, name: str) -> SectionHeader | None:
        """Return the section named ``name`` or ``None`` when absent."""
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def has_section(self, name: str) -> bool:
        return self.section(name) is not None

    def symbols_from(self, table: str) -> tuple[Symbol, ...]:
        """Return symbols decoded from ``table`` (``.dynsym`` or ``.symtab``)."""
        return tuple(symbol for symbol in self.symbols if symbol.table == table)

    @property
    def symbol_tables(self) -> tuple[str, ...]:
        tables: list[str] = []
        for symbol in self.symbols:
            if symbol.table not in tables:
                tables.append(symbol.table)
        return tuple(tables)

    def relro_mode(self) -> str | None:
        """Classify the relocation hardening of the image.

        Returns ``"full"``, ``"partial"``, ``"none"`` or ``None`` when the
        image carries no program headers and the mode cannot be known.

        ``full`` means every writable relocation target -- the GOT in
        practice -- is covered by the ``PT_GNU_RELRO`` segment, or the
        dynamic linker resolves everything at load time (``BIND_NOW``).
        ``partial`` means a RELRO segment exists but the GOT stays writable.
        """
        if not self.program_headers:
            return None
        relro = next(
            (ph for ph in self.program_headers if ph.type == "GNU_RELRO"), None
        )
        if relro is None:
            return "none"
        if self.dynamic.bind_now:
            return "full"
        if not self.sections:
            # Without a section table the GOT cannot be located, so the
            # difference between full and partial RELRO is unknown.
            return None
        got = self.section(".got.plt") or self.section(".got")
        if got is None or got.size <= 0:
            # No writable relocation target exists, so nothing stays
            # unprotected inside the RELRO segment.
            return "full"
        start = relro.virtual_address
        end = start + relro.memory_size
        if start <= got.address and got.address + got.size <= end:
            return "full"
        return "partial"

    @property
    def is_stripped(self) -> bool:
        """True when no regular (non-dynamic) symbol table is present."""
        return not self.has_section(elf.SECTION_SYMTAB)

    def hardening_facts(self) -> dict[str, bool | None]:
        """Return linker/compiler hardening facts derived from the image.

        The program-header facts come from ``PT_GNU_RELRO`` / ``PT_GNU_STACK``;
        the compiler facts come from the symbol table (stack canary, CFI) and
        the ``GNU_PROPERTY`` note (AArch64 PAC). ``None`` means "unknown": the
        relevant table or note is absent or truncated, which must never be
        reported as the absence of a feature.
        """
        facts: dict[str, bool | None | str] = {
            "has_gnu_relro": None,
            "executable_stack": None,
            "has_stack_canary": None,
            "has_cfi": None,
            "has_pac": None,
            "relro_mode": None,
        }
        has_relro: bool | None = None
        executable_stack: bool | None = None
        if self.program_headers:
            has_relro = False
        for program_header in self.program_headers:
            if program_header.type == "GNU_RELRO":
                has_relro = True
            elif program_header.type == "GNU_STACK":
                executable_stack = program_header.is_executable
        facts["has_gnu_relro"] = has_relro
        facts["executable_stack"] = executable_stack
        facts["relro_mode"] = self.relro_mode()

        if self.symbol_tables:
            facts["has_stack_canary"] = _references_any(
                self.symbols, ("__stack_chk_fail", "__stack_chk_guard")
            )
            facts["has_cfi"] = _references_prefix(self.symbols, ("__cfi_slowpath", "__cfi_check"))
        if self.aarch64_feature_1 is not None:
            facts["has_pac"] = bool(
                self.aarch64_feature_1 & elf.GNU_PROPERTY_AARCH64_FEATURE_1_PAC
            )
        return facts


def parse_elf(path: Path) -> ElfFile:
    """Parse the ELF image at ``path``.

    Raises:
        ElfFormatError: the file is empty or not a valid ELF image.
        OSError: the file exists but cannot be read.
    """
    with open(path, "rb") as handle:
        mapped: _BytesLike | None = None
        try:
            mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            # Empty files cannot be mapped; fall back to an in-memory read.
            mapped = handle.read()
        try:
            return parse_bytes(mapped)
        finally:
            if isinstance(mapped, mmap.mmap):
                mapped.close()


def parse_bytes(data: _BytesLike) -> ElfFile:
    """Parse ELF structures from an in-memory image."""
    if len(data) < 16:
        raise ElfFormatError("file is too small to be an ELF image")
    if bytes(data[:4]) != elf.ELF_MAGIC:
        raise ElfFormatError("missing ELF magic bytes")

    ei_class = data[elf.EI_CLASS]
    ei_data = data[elf.EI_DATA]
    if ei_class not in (elf.ELFCLASS32, elf.ELFCLASS64):
        raise ElfFormatError(f"unsupported ELF class {ei_class}")
    if ei_data not in (elf.ELFDATA2LSB, elf.ELFDATA2MSB):
        raise ElfFormatError(f"unsupported ELF data encoding {ei_data}")

    prefix = "<" if ei_data == elf.ELFDATA2LSB else ">"
    is64 = ei_class == elf.ELFCLASS64
    if len(data) < (_ELF64_HEADER_SIZE if is64 else _ELF32_HEADER_SIZE):
        raise ElfFormatError("truncated ELF header")

    header_fields = _ELF64_HEADER_FIELDS if is64 else _ELF32_HEADER_FIELDS
    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from(prefix + header_fields, data, 16)

    header = ElfHeader(
        elf_class=elf.ELFCLASS_NAMES[ei_class],
        endianness=elf.ENDIANNESS_NAMES[ei_data],
        os_abi=elf.OSABI_NAMES.get(data[elf.EI_OSABI], str(data[elf.EI_OSABI])),
        abi_version=data[8],
        type=elf.ET_NAMES.get(e_type, str(e_type)),
        machine=elf.EM_NAMES.get(e_machine, str(e_machine)),
        entry_point=e_entry,
        program_header_offset=e_phoff,
        section_header_offset=e_shoff,
        flags=e_flags,
        header_size=e_ehsize,
        program_header_entry_size=e_phentsize,
        program_header_count=e_phnum,
        section_header_entry_size=e_shentsize,
        section_header_count=e_shnum,
        section_name_table_index=e_shstrndx,
    )

    program_headers = _parse_program_headers(data, prefix, is64, header)
    raw_sections = _parse_section_headers(data, prefix, is64, header)
    sections = _resolve_section_names(data, raw_sections, header.section_name_table_index)
    symbols = _parse_symbols(data, prefix, is64, sections)
    dynsym = tuple(symbol for symbol in symbols if symbol.table == elf.SECTION_DYNSYM)
    return ElfFile(
        header=header,
        program_headers=program_headers,
        sections=sections,
        symbols=symbols,
        aarch64_feature_1=_parse_aarch64_feature_1(
            data, prefix, program_headers, sections
        ),
        dynamic=parse_dynamic_info(
            data,
            prefix=prefix,
            is64=is64,
            sections=sections,
            program_headers=program_headers,
            dynsym=dynsym,
        ),
        relocations=parse_relocations(
            data,
            prefix=prefix,
            is64=is64,
            sections=sections,
            dynsym=dynsym,
        ),
    )


def _check_range(data: _BytesLike, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ElfFormatError(f"{what} extends past end of file")


def _in_range(data: _BytesLike, offset: int, size: int) -> bool:
    """True when ``[offset, offset+size)`` lies inside ``data``."""
    return offset >= 0 and size >= 0 and offset + size <= len(data)


def _read_bytes(data: _BytesLike, offset: int, size: int, what: str) -> bytes:
    _check_range(data, offset, size, what)
    return bytes(data[offset : offset + size])


def _read_optional_bytes(data: _BytesLike, offset: int, size: int) -> bytes:
    """Read a table, returning ``b""`` when it lies past end of file.

    A declared-but-absent table means "unknown", not "invalid": the header of
    a truncated image still parses, and callers must treat the missing facts
    as absent rather than as a negative answer.
    """
    if not _in_range(data, offset, size):
        return b""
    return bytes(data[offset : offset + size])


def _parse_program_headers(
    data: _BytesLike,
    prefix: str,
    is64: bool,
    header: ElfHeader,
) -> tuple[ProgramHeader, ...]:
    count = header.program_header_count
    offset = header.program_header_offset
    entry_size = header.program_header_entry_size
    if count == 0 or offset == 0:
        return ()
    if entry_size < (_ELF64_PHDR_SIZE if is64 else _ELF32_PHDR_SIZE):
        raise ElfFormatError("program header entry size is too small")
    raw = _read_optional_bytes(data, offset, count * entry_size)
    if not raw:
        return ()

    fields = _ELF64_PHDR_FIELDS if is64 else _ELF32_PHDR_FIELDS
    headers: list[ProgramHeader] = []
    for index in range(count):
        values = struct.unpack_from(prefix + fields, raw, index * entry_size)
        if is64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = values
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = values
        headers.append(
            ProgramHeader(
                type=elf.PT_NAMES.get(p_type, str(p_type)),
                flags=p_flags,
                offset=p_offset,
                virtual_address=p_vaddr,
                physical_address=p_paddr,
                file_size=p_filesz,
                memory_size=p_memsz,
                alignment=p_align,
            )
        )
    return tuple(headers)


def _parse_section_headers(
    data: _BytesLike,
    prefix: str,
    is64: bool,
    header: ElfHeader,
) -> tuple[tuple[int, SectionHeader], ...]:
    """Return ``(sh_name offset, SectionHeader)`` pairs; names are resolved later."""
    count = header.section_header_count
    offset = header.section_header_offset
    entry_size = header.section_header_entry_size
    if count == 0 or offset == 0:
        return ()
    if entry_size < (_ELF64_SHDR_SIZE if is64 else _ELF32_SHDR_SIZE):
        raise ElfFormatError("section header entry size is too small")
    raw = _read_optional_bytes(data, offset, count * entry_size)
    if not raw:
        return ()

    fields = _ELF64_SHDR_FIELDS if is64 else _ELF32_SHDR_FIELDS
    sections: list[tuple[int, SectionHeader]] = []
    for index in range(count):
        values = struct.unpack_from(prefix + fields, raw, index * entry_size)
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) = values
        sections.append(
            (
                sh_name,
                SectionHeader(
                    index=index,
                    name="",
                    type=elf.SHT_NAMES.get(sh_type, str(sh_type)),
                    type_value=sh_type,
                    flags=sh_flags,
                    address=sh_addr,
                    offset=sh_offset,
                    size=sh_size,
                    link=sh_link,
                    info=sh_info,
                    alignment=sh_addralign,
                    entry_size=sh_entsize,
                ),
            )
        )
    return tuple(sections)


def _resolve_section_names(
    data: _BytesLike,
    raw_sections: tuple[tuple[int, SectionHeader], ...],
    name_table_index: int,
) -> tuple[SectionHeader, ...]:
    """Fill in section names from the ``.shstrtab`` section."""
    if not raw_sections:
        return ()
    if not 0 <= name_table_index < len(raw_sections):
        return tuple(section for _, section in raw_sections)
    name_table = raw_sections[name_table_index][1]
    if name_table.type_value != elf.SHT_STRTAB:
        return tuple(section for _, section in raw_sections)
    strings = _read_optional_bytes(data, name_table.offset, name_table.size)

    resolved: list[SectionHeader] = []
    for name_offset, section in raw_sections:
        resolved.append(
            SectionHeader(
                index=section.index,
                name=_string_at(strings, name_offset),
                type=section.type,
                type_value=section.type_value,
                flags=section.flags,
                address=section.address,
                offset=section.offset,
                size=section.size,
                link=section.link,
                info=section.info,
                alignment=section.alignment,
                entry_size=section.entry_size,
            )
        )
    return tuple(resolved)


def _parse_symbols(
    data: _BytesLike,
    prefix: str,
    is64: bool,
    sections: tuple[SectionHeader, ...],
) -> tuple[Symbol, ...]:
    symbols: list[Symbol] = []
    for table_name, section_type in (
        (elf.SECTION_DYNSYM, elf.SHT_DYNSYM),
        (elf.SECTION_SYMTAB, elf.SHT_SYMTAB),
    ):
        table = next(
            (section for section in sections if section.type_value == section_type),
            None,
        )
        if table is None or table.entry_size == 0 or table.size == 0:
            continue
        symbols.extend(_parse_symbol_table(data, prefix, is64, table, sections, table_name))
    return tuple(symbols)


def _parse_symbol_table(
    data: _BytesLike,
    prefix: str,
    is64: bool,
    table: SectionHeader,
    sections: tuple[SectionHeader, ...],
    table_name: str,
) -> tuple[Symbol, ...]:
    expected = _ELF64_SYM_SIZE if is64 else _ELF32_SYM_SIZE
    if table.entry_size < expected:
        return ()
    count = table.size // table.entry_size
    raw = _read_optional_bytes(data, table.offset, count * table.entry_size)
    if not raw:
        return ()

    string_table = sections[table.link] if 0 <= table.link < len(sections) else None
    strings = b""
    if string_table is not None and string_table.type_value == elf.SHT_STRTAB:
        strings = _read_optional_bytes(
            data, string_table.offset, string_table.size
        )

    fields = _ELF64_SYM_FIELDS if is64 else _ELF32_SYM_FIELDS
    symbols: list[Symbol] = []
    for index in range(count):
        values = struct.unpack_from(prefix + fields, raw, index * table.entry_size)
        if is64:
            st_name, st_info, st_other, st_shndx, st_value, st_size = values
        else:
            st_name, st_value, st_size, st_info, st_other, st_shndx = values
        symbols.append(
            Symbol(
                name=_string_at(strings, st_name),
                bind=elf.STB_NAMES.get(st_info >> 4, str(st_info >> 4)),
                type=elf.STT_NAMES.get(st_info & 0xF, str(st_info & 0xF)),
                type_value=st_info & 0xF,
                visibility=elf.STV_NAMES.get(st_other & 0x3, str(st_other & 0x3)),
                section_index=st_shndx,
                value=st_value,
                size=st_size,
                table=table_name,
            )
        )
    return tuple(symbols)


def _string_at(table: bytes, offset: int) -> str:
    """Read a NUL-terminated string from ``table``, tolerating truncation."""
    if offset <= 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("utf-8", errors="replace")


def _references_any(symbols: tuple[Symbol, ...], names: tuple[str, ...]) -> bool:
    """True when the symbol table references any of ``names``."""
    wanted = set(names)
    return any(symbol.name in wanted for symbol in symbols)


def _references_prefix(symbols: tuple[Symbol, ...], prefixes: tuple[str, ...]) -> bool:
    """True when the symbol table references a symbol with any prefix."""
    return any(
        symbol.name.startswith(prefix)
        for symbol in symbols
        for prefix in prefixes
    )


def _parse_aarch64_feature_1(
    data: _BytesLike,
    prefix: str,
    program_headers: tuple[ProgramHeader, ...],
    sections: tuple[SectionHeader, ...],
) -> int | None:
    """Return the AArch64 feature-1 mask from a GNU_PROPERTY note.

    ``None`` means no GNU property note was found, so the presence of PAC must
    be reported as unknown instead of as a negative answer.
    """
    region = _gnu_property_region(data, program_headers, sections)
    if region is None:
        return None
    offset, size = region
    for description, note_type in _iter_notes(data, prefix, offset, size):
        if note_type != elf.GNU_PROPERTY_TYPE_0:
            continue
        feature = _parse_property(
            description, prefix, elf.GNU_PROPERTY_AARCH64_FEATURE_1_AND
        )
        if feature is not None:
            return feature
    return None


def _gnu_property_region(
    data: _BytesLike,
    program_headers: tuple[ProgramHeader, ...],
    sections: tuple[SectionHeader, ...],
) -> tuple[int, int] | None:
    """Locate the GNU property note in a program header or a section."""
    for program_header in program_headers:
        if program_header.type != elf.PT_NAMES[elf.PT_GNU_PROPERTY]:
            continue
        if _in_range(data, program_header.offset, program_header.file_size):
            return program_header.offset, program_header.file_size
    for section in sections:
        if section.type_value != elf.SHT_NOTE:
            continue
        if not (
            section.name == elf.SECTION_NOTE_GNU_PROPERTY
            or section.name.startswith(".note.gnu")
        ):
            continue
        if _in_range(data, section.offset, section.size):
            return section.offset, section.size
    return None


def _iter_notes(
    data: _BytesLike, prefix: str, offset: int, size: int
) -> Iterable[tuple[bytes, int]]:
    """Yield ``(description, type)`` for each note inside an aligned region."""
    end = offset + size
    position = offset
    note_format = prefix + "III"
    while position + 12 <= end:
        namesz, descsz, note_type = struct.unpack_from(note_format, data, position)
        if namesz > end - position - 12:
            return
        description_offset = position + 12 + namesz
        # GNU notes round name/description up to a 4-byte word boundary.
        description_offset = (description_offset + 3) & ~3
        if descsz > end - description_offset:
            return
        description = bytes(data[description_offset : description_offset + descsz])
        yield description, note_type
        position = description_offset + descsz
        position = (position + 3) & ~3


def _parse_property(
    description: bytes, prefix: str, target_type: int
) -> int | None:
    """Return the 4-byte value of ``target_type`` inside a property list."""
    end = len(description)
    position = 0
    pair_format = prefix + "II"
    while position + 8 <= end:
        prop_type, data_size = struct.unpack_from(pair_format, description, position)
        data_offset = position + 8
        if data_size > end - data_offset:
            return None
        if prop_type == target_type and data_size >= 4:
            return struct.unpack_from(prefix + "I", description, data_offset)[0]
        position = data_offset + data_size
        position = (position + 3) & ~3
    return None
