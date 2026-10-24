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
from typing import Union

from . import constants as elf
from .structures import ElfHeader, ProgramHeader, SectionHeader, Symbol


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

    @property
    def is_stripped(self) -> bool:
        """True when no regular (non-dynamic) symbol table is present."""
        return not self.has_section(elf.SECTION_SYMTAB)

    def hardening_facts(self) -> dict[str, bool | None]:
        """Return NX/RELRO facts derived from the program header table.

        ``None`` means "unknown": the table is absent or truncated, which must
        never be reported as the absence of a feature.
        """
        if not self.program_headers:
            return {"has_gnu_relro": None, "executable_stack": None}
        has_relro: bool | None = False
        executable_stack: bool | None = None
        for program_header in self.program_headers:
            if program_header.type == "GNU_RELRO":
                has_relro = True
            elif program_header.type == "GNU_STACK":
                executable_stack = program_header.is_executable
        return {"has_gnu_relro": has_relro, "executable_stack": executable_stack}


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
    return ElfFile(
        header=header,
        program_headers=program_headers,
        sections=sections,
        symbols=symbols,
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
