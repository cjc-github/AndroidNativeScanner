"""Dynamic-linking facts: the ``.dynamic`` table and symbol versioning.

A shared object is mostly a set of promises about how the dynamic linker
will resolve it.  Those promises live in tables that a header/symbol parse
never touches:

* ``.dynamic`` — the dependency list (``DT_NEEDED``), the object's own name
  (``DT_SONAME``), the library search path (``DT_RPATH`` / ``DT_RUNPATH``)
  and the constructor/destructor arrays the loader runs around ``main``;
* ``.gnu.version_d`` / ``.gnu.version_r`` / ``.gnu.version`` — the symbol
  versions an image defines and the versions it demands of its dependencies.

Everything is decoded with :mod:`struct`, so no external toolchain is
needed, and every read is bounds-checked: a truncated table yields the facts
that are still readable instead of raising.
"""

from __future__ import annotations

import struct
from typing import Iterable

from . import constants as elf
from .structures import (
    DynamicEntry,
    DynamicInfo,
    ProgramHeader,
    SectionHeader,
    Symbol,
    SymbolVersion,
    VersionDefinition,
    VersionRequirement,
)

_DYNAMIC_SECTION_TYPE = 6  # SHT_DYNAMIC


def parse_dynamic_info(
    data,
    *,
    prefix: str,
    is64: bool,
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
    dynsym: tuple[Symbol, ...] = (),
) -> DynamicInfo:
    """Decode the dynamic-linking facts of one image.

    ``data`` is the raw image, ``prefix`` the struct format character for the
    image's endianness and ``is64`` its ELF class.  Absent tables are not an
    error: the result simply carries no entries for them.
    """
    entries = _read_dynamic_entries(data, prefix, is64, sections, program_headers)
    if not entries:
        return DynamicInfo()

    values = {entry.tag_value: entry.value for entry in entries}
    # A tag may repeat (DT_NEEDED lists one entry per dependency), so the
    # multi-valued tags are collected from the entry list, not the map.
    needed_offsets = tuple(
        entry.value for entry in entries if entry.tag_value == elf.DT_NEEDED
    )

    strtab_offset = _strtab_offset(values, sections, program_headers)
    needed = _strings_at(data, strtab_offset, needed_offsets)
    soname = _first_string(data, strtab_offset, values.get(elf.DT_SONAME))
    rpath = _first_string(data, strtab_offset, values.get(elf.DT_RPATH))
    runpath = _first_string(data, strtab_offset, values.get(elf.DT_RUNPATH))

    init_array = _read_pointer_array(
        data,
        prefix,
        is64,
        values.get(elf.DT_INIT_ARRAY),
        values.get(elf.DT_INIT_ARRAYSZ),
        sections,
        program_headers,
    )
    fini_array = _read_pointer_array(
        data,
        prefix,
        is64,
        values.get(elf.DT_FINI_ARRAY),
        values.get(elf.DT_FINI_ARRAYSZ),
        sections,
        program_headers,
    )
    preinit_array = _read_pointer_array(
        data,
        prefix,
        is64,
        values.get(elf.DT_PREINIT_ARRAY),
        values.get(elf.DT_PREINIT_ARRAYSZ),
        sections,
        program_headers,
    )

    flags = values.get(elf.DT_FLAGS, 0)
    flags_1 = values.get(elf.DT_FLAGS_1, 0)
    bind_now = (
        elf.DT_BIND_NOW in values
        or bool(flags & elf.DF_BIND_NOW)
        or bool(flags_1 & elf.DF_1_NOW)
    )
    has_textrel = elf.DT_TEXTREL in values or bool(flags & elf.DF_TEXTREL)

    definitions, requirements = _parse_version_tables(
        data, prefix, sections, program_headers
    )
    symbol_versions = _bind_symbol_versions(
        data, prefix, sections, dynsym, definitions
    )

    return DynamicInfo(
        entries=entries,
        needed=needed,
        soname=soname,
        rpath=rpath,
        runpath=runpath,
        init=values.get(elf.DT_INIT),
        fini=values.get(elf.DT_FINI),
        init_array=init_array,
        fini_array=fini_array,
        preinit_array=preinit_array,
        flags=flags,
        flags_1=flags_1,
        bind_now=bind_now,
        has_textrel=has_textrel,
        version_definitions=definitions,
        version_requirements=requirements,
        symbol_versions=symbol_versions,
    )


# --- .dynamic table ---------------------------------------------------------


def _read_dynamic_entries(
    data,
    prefix: str,
    is64: bool,
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
) -> tuple[DynamicEntry, ...]:
    """Decode the ``.dynamic`` table into ``(tag, value)`` pairs."""
    region = _dynamic_region(sections, program_headers)
    if region is None:
        return ()
    offset, size = region
    if size <= 0:
        return ()

    entry_size = 16 if is64 else 8
    fmt = prefix + ("qQ" if is64 else "iI")
    entries: list[DynamicEntry] = []
    position = offset
    limit = offset + size
    while position + entry_size <= limit and position + entry_size <= len(data):
        tag, value = struct.unpack_from(fmt, data, position)
        if tag == elf.DT_NULL:
            break
        entries.append(
            DynamicEntry(
                tag=elf.DT_NAMES.get(tag, str(tag)),
                tag_value=tag,
                value=value,
            )
        )
        position += entry_size
    return tuple(entries)


def _dynamic_region(
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
) -> tuple[int, int] | None:
    """Locate the ``.dynamic`` table as a file offset and size."""
    for section in sections:
        if section.type_value == _DYNAMIC_SECTION_TYPE and section.size > 0:
            return section.offset, section.size
    for program_header in program_headers:
        if program_header.type == "DYNAMIC" and program_header.file_size > 0:
            return program_header.offset, program_header.file_size
    return None


# --- address and string helpers --------------------------------------------


def address_to_offset(
    address: int,
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
) -> int | None:
    """Translate a virtual address into a file offset.

    Sections are consulted first because they carry the exact file extent of
    a table; the loadable segments are the fallback for addresses that live
    outside any section.  ``SHT_NOBITS`` sections have no file content and
    are skipped.
    """
    for section in sections:
        if section.size <= 0 or not section.address:
            continue
        if section.type_value == 8:  # SHT_NOBITS occupies no file bytes
            continue
        if section.address <= address < section.address + section.size:
            return section.offset + (address - section.address)
    for program_header in program_headers:
        if program_header.type != "LOAD" or program_header.file_size <= 0:
            continue
        start = program_header.virtual_address
        if start <= address < start + program_header.file_size:
            return program_header.offset + (address - start)
    return None


def _strtab_offset(
    values: dict[int, int],
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
) -> int | None:
    """File offset of the dynamic string table."""
    address = values.get(elf.DT_STRTAB)
    if address is None:
        return None
    return address_to_offset(address, sections, program_headers)


def _read_cstring(data, offset: int | None) -> str | None:
    """Read a NUL-terminated string, or ``None`` when it cannot be read."""
    if offset is None or offset < 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _strings_at(data, strtab_offset: int | None, offsets: Iterable[int]) -> tuple[str, ...]:
    """Read every string the given ``.dynstr`` offsets point at."""
    if strtab_offset is None:
        return ()
    values: list[str] = []
    for offset in offsets:
        text = _read_cstring(data, strtab_offset + offset)
        if text:
            values.append(text)
    return tuple(values)


def _first_string(data, strtab_offset: int | None, offset: int | None) -> str | None:
    """Read the single string an optional tag points at."""
    if strtab_offset is None or offset is None:
        return None
    return _read_cstring(data, strtab_offset + offset)


def _read_pointer_array(
    data,
    prefix: str,
    is64: bool,
    address: int | None,
    size: int | None,
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
) -> tuple[int, ...]:
    """Read an array of function pointers declared by a dynamic tag."""
    if address is None or not size:
        return ()
    offset = address_to_offset(address, sections, program_headers)
    if offset is None or offset < 0:
        return ()
    width = 8 if is64 else 4
    count = size // width
    fmt = prefix + ("Q" if is64 else "I")
    pointers: list[int] = []
    for index in range(count):
        position = offset + index * width
        if position + width > len(data):
            break
        (value,) = struct.unpack_from(fmt, data, position)
        pointers.append(value)
    return tuple(pointers)


# --- symbol versioning ------------------------------------------------------


def _parse_version_tables(
    data,
    prefix: str,
    sections: tuple[SectionHeader, ...],
    program_headers: tuple[ProgramHeader, ...],
) -> tuple[tuple[VersionDefinition, ...], tuple[VersionRequirement, ...]]:
    """Decode ``.gnu.version_d`` and ``.gnu.version_r``."""
    definitions = _parse_verdefs(data, prefix, sections)
    requirements = _parse_verneeds(data, prefix, sections)
    return definitions, requirements


def _section_by_type(
    sections: tuple[SectionHeader, ...], type_value: int
) -> SectionHeader | None:
    for section in sections:
        if section.type_value == type_value:
            return section
    return None


def _linked_strings(
    data, sections: tuple[SectionHeader, ...], section: SectionHeader
) -> bytes:
    """The string table a metadata section links to through ``sh_link``."""
    if not 0 <= section.link < len(sections):
        return b""
    linked = sections[section.link]
    if linked.size <= 0:
        return b""
    start = linked.offset
    end = start + linked.size
    if start < 0 or end > len(data):
        return b""
    return bytes(data[start:end])


def _string_from(table: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("utf-8", errors="replace")


def _parse_verdefs(
    data, prefix: str, sections: tuple[SectionHeader, ...]
) -> tuple[VersionDefinition, ...]:
    """Decode the versions an image defines for itself."""
    section = _section_by_type(sections, elf.SHT_GNU_VERDEF)
    if section is None or section.size <= 0:
        return ()
    table = _linked_strings(data, sections, section)
    definitions: list[VersionDefinition] = []
    position = section.offset
    limit = section.offset + section.size
    while position + 20 <= limit and position + 20 <= len(data):
        (
            _vd_version,
            vd_flags,
            vd_ndx,
            _vd_cnt,
            _vd_hash,
            vd_aux,
            vd_next,
        ) = struct.unpack_from(prefix + "HHHHIII", data, position)
        name = _verdef_name(data, prefix, table, position, vd_aux, limit)
        definitions.append(
            VersionDefinition(
                index=vd_ndx & elf.VERSYM_VERSION,
                name=name,
                is_base=bool(vd_flags & elf.VER_FLG_BASE),
            )
        )
        if vd_next == 0:
            break
        position += vd_next
    return tuple(definitions)


def _verdef_name(
    data,
    prefix: str,
    table: bytes,
    position: int,
    vd_aux: int,
    limit: int,
) -> str:
    """The version name a ``Elf64_Verdef`` entry points at.

    ``vd_aux`` is the offset of the auxiliary entry, not of the name: the
    name offset lives in ``Elf64_Verdaux.vda_name``.
    """
    aux_position = position + vd_aux
    if aux_position + 8 > limit or aux_position + 8 > len(data):
        return ""
    vda_name, _vda_next = struct.unpack_from(prefix + "II", data, aux_position)
    return _string_from(table, vda_name)


def _parse_verneeds(
    data, prefix: str, sections: tuple[SectionHeader, ...]
) -> tuple[VersionRequirement, ...]:
    """Decode the versions an image demands of its dependencies."""
    section = _section_by_type(sections, elf.SHT_GNU_VERNEED)
    if section is None or section.size <= 0:
        return ()
    table = _linked_strings(data, sections, section)
    requirements: list[VersionRequirement] = []
    position = section.offset
    limit = section.offset + section.size
    while position + 16 <= limit and position + 16 <= len(data):
        _vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(
            prefix + "HHIII", data, position
        )
        file_name = _string_from(table, vn_file)
        aux_position = position + vn_aux
        for _ in range(vn_cnt):
            if aux_position + 16 > limit or aux_position + 16 > len(data):
                break
            _vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from(
                prefix + "IHHII", data, aux_position
            )
            requirements.append(
                VersionRequirement(
                    name=_string_from(table, vna_name),
                    file=file_name,
                    index=vna_other & elf.VERSYM_VERSION,
                    flags=vna_flags,
                )
            )
            if vna_next == 0:
                break
            aux_position += vna_next
        if vn_next == 0:
            break
        position += vn_next
    return tuple(requirements)


def _bind_symbol_versions(
    data,
    prefix: str,
    sections: tuple[SectionHeader, ...],
    dynsym: tuple[Symbol, ...],
    definitions: tuple[VersionDefinition, ...],
) -> tuple[SymbolVersion, ...]:
    """Map every dynamic symbol onto the version it belongs to."""
    section = _section_by_type(sections, elf.SHT_GNU_VERSYM)
    if section is None or section.size <= 0 or not dynsym:
        return ()
    count = min(section.size // 2, len(dynsym))
    if count <= 0:
        return ()
    names = {definition.index: definition.name for definition in definitions}
    base = next(
        (definition.name for definition in definitions if definition.is_base), None
    )

    versions: list[SymbolVersion] = []
    for index in range(count):
        (raw,) = struct.unpack_from(prefix + "H", data, section.offset + index * 2)
        version_index = raw & elf.VERSYM_VERSION
        hidden = bool(raw & elf.VERSYM_HIDDEN)
        if version_index == elf.VER_NDX_LOCAL:
            name = ""
        elif version_index == elf.VER_NDX_GLOBAL:
            name = base or ""
        else:
            name = names.get(version_index, "")
        versions.append(SymbolVersion(name=name, index=version_index, hidden=hidden))
    return tuple(versions)
