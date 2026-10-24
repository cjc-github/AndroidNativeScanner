"""DWARF debug-information parser.

Reads ``.debug_info``, ``.debug_abbrev``, ``.debug_str``, ``.debug_line_str``
and the ``.debug_line`` header, and returns the subprograms with their formal
parameters, parameter types, return types and source locations.

Only the subset that describes functions is decoded. Unknown attributes and
forms are skipped rather than guessed at: a wrong parameter name is worse than
a missing one, so anything unreadable degrades to ``None`` and the caller
reports what it could prove.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from ..elf import parse_elf
from . import constants as dwarf
from .constants import (
    _NAMESPACE_TAGS,
    DW_AT_abstract_origin,
    DW_AT_comp_dir,
    DW_AT_decl_file,
    DW_AT_decl_line,
    DW_AT_high_pc,
    DW_AT_linkage_name,
    DW_AT_low_pc,
    DW_AT_name,
    DW_AT_specification,
    DW_AT_stmt_list,
    DW_AT_type,
    DW_FORM_addr,
    DW_FORM_addrx,
    DW_FORM_addrx1,
    DW_FORM_addrx2,
    DW_FORM_addrx3,
    DW_FORM_addrx4,
    DW_FORM_block,
    DW_FORM_block1,
    DW_FORM_block2,
    DW_FORM_block4,
    DW_FORM_data1,
    DW_FORM_data16,
    DW_FORM_data2,
    DW_FORM_data4,
    DW_FORM_data8,
    DW_FORM_exprloc,
    DW_FORM_flag,
    DW_FORM_flag_present,
    DW_FORM_implicit_const,
    DW_FORM_indirect,
    DW_FORM_line_strp,
    DW_FORM_ref1,
    DW_FORM_ref2,
    DW_FORM_ref4,
    DW_FORM_ref8,
    DW_FORM_ref_addr,
    DW_FORM_ref_udata,
    DW_FORM_sdata,
    DW_FORM_sec_offset,
    DW_FORM_strp,
    DW_FORM_string,
    DW_FORM_strx,
    DW_FORM_strx1,
    DW_FORM_strx2,
    DW_FORM_strx3,
    DW_FORM_strx4,
    DW_FORM_udata,
    DW_TAG_array_type,
    DW_TAG_class_type,
    DW_TAG_compile_unit,
    DW_TAG_const_type,
    DW_TAG_enumeration_type,
    DW_TAG_formal_parameter,
    DW_TAG_pointer_type,
    DW_TAG_reference_type,
    DW_TAG_restrict_type,
    DW_TAG_structure_type,
    DW_TAG_subprogram,
    DW_TAG_subroutine_type,
    DW_TAG_typedef,
    DW_TAG_union_type,
    DW_TAG_variable,
    DW_TAG_volatile_type,
)
from .structures import DwarfFunction, DwarfInfo, DwarfParameter

_MAX_DIES = 2_000_000
_MAX_TYPE_DEPTH = 12


class DwarfFormatError(ValueError):
    """The debug information is malformed or uses an unsupported layout."""


@dataclass
class _Attribute:
    name: int
    value: object


@dataclass
class _Abbrev:
    code: int
    tag: int
    has_children: bool
    attributes: tuple[tuple[int, int, int], ...] = ()  # (attr, form, implicit_const)


@dataclass
class _Die:
    offset: int
    tag: int
    attributes: tuple[_Attribute, ...] = ()
    children: tuple["_Die", ...] = ()
    parent: "_Die | None" = None

    def get(self, name: int) -> object | None:
        for attribute in self.attributes:
            if attribute.name == name:
                return attribute.value
        return None

    def child(self, tag: int) -> "_Die | None":
        for die in self.children:
            if die.tag == tag:
                return die
        return None

    def children_with_tag(self, tag: int) -> tuple["_Die", ...]:
        return tuple(die for die in self.children if die.tag == tag)

    def enclosing_names(self) -> tuple[str, ...]:
        """Collect enclosing namespace and class names, outermost first.

        DW_AT_name holds the unqualified source name, so a method's class and
        namespaces live in the parent chain instead.
        """
        names: list[str] = []
        parent = self.parent
        while parent is not None:
            if parent.tag in _NAMESPACE_TAGS:
                name = parent.get(DW_AT_name)
                if isinstance(name, str) and name:
                    names.append(name)
            parent = parent.parent
        return tuple(reversed(names))


@dataclass
class _Unit:
    offset: int
    version: int
    offset_size: int
    dies: tuple[_Die, ...] = field(default_factory=tuple)
    line_files: tuple[str, ...] = ()


# --- primitive decoding ------------------------------------------------------


def _read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise DwarfFormatError("truncated ULEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 64:
            raise DwarfFormatError("ULEB128 too long")


def _read_sleb(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise DwarfFormatError("truncated SLEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            return result, offset
        if shift > 64:
            raise DwarfFormatError("SLEB128 too long")


def _read_cstr(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end == -1:
        raise DwarfFormatError("unterminated string")
    return data[offset:end].decode("utf-8", errors="replace"), end + 1


# --- abbreviation tables -----------------------------------------------------


def _parse_abbreviations(data: bytes, offset: int) -> dict[int, _Abbrev]:
    table: dict[int, _Abbrev] = {}
    while True:
        code, offset = _read_uleb(data, offset)
        if code == 0:
            break
        if code in table:
            raise DwarfFormatError(f"duplicate abbreviation code {code}")
        tag, offset = _read_uleb(data, offset)
        if offset >= len(data):
            raise DwarfFormatError("truncated abbreviation")
        has_children = bool(data[offset])
        offset += 1
        attributes: list[tuple[int, int, int]] = []
        while True:
            attr, offset = _read_uleb(data, offset)
            form, offset = _read_uleb(data, offset)
            if attr == 0 and form == 0:
                break
            implicit = 0
            if form == DW_FORM_implicit_const:
                implicit, offset = _read_sleb(data, offset)
            attributes.append((attr, form, implicit))
        table[code] = _Abbrev(
            code=code, tag=tag, has_children=has_children, attributes=tuple(attributes)
        )
    return table


# --- line program header -----------------------------------------------------


def _parse_line_file_names(
    data: bytes, offset: int, version: int, offset_size: int
) -> tuple[tuple[str, ...], int]:
    """Read the file-name table from a ``.debug_line`` unit header.

    Returns the file names (resolved against their include directory when the
    header provides one) and the offset just past the header.
    """
    try:
        if version >= 5:
            return _parse_line_header_v5(data, offset, offset_size)
        return _parse_line_header_v4(data, offset, offset_size)
    except (DwarfFormatError, struct.error, IndexError):
        # A missing file table must not lose the parameters: the caller falls
        # back to reporting the raw declaration-file index.
        return (), offset


def _parse_line_header_v4(
    data: bytes, offset: int, offset_size: int
) -> tuple[tuple[str, ...], int]:
    """Read the DWARF 2-4 line program header."""
    _unit_length, offset, _dwarf64 = _read_initial_length(data, offset)
    (version,) = struct.unpack_from("<H", data, offset)
    offset += 2
    header_length_fmt = "<I" if offset_size == 4 else "<Q"
    (header_length,) = struct.unpack_from(header_length_fmt, data, offset)
    offset += offset_size
    header_end = offset + header_length

    offset += 1  # minimum_instruction_length
    if version >= 4:
        offset += 1  # maximum_operations_per_instruction
    offset += 1  # default_is_stmt
    offset += 1  # line_base
    offset += 1  # line_range
    opcode_base = data[offset]
    offset += 1
    offset += opcode_base - 1  # standard_opcode_lengths

    directories: list[str] = []
    while True:
        name, offset = _read_cstr(data, offset)
        if not name:
            break
        directories.append(name)

    files: list[str] = []
    while True:
        name, offset = _read_cstr(data, offset)
        if not name:
            break
        dir_index, offset = _read_uleb(data, offset)
        _mtime, offset = _read_uleb(data, offset)
        _size, offset = _read_uleb(data, offset)
        prefix = ""
        if isinstance(dir_index, int) and 0 < dir_index <= len(directories):
            prefix = directories[dir_index - 1] + "/"
        files.append(f"{prefix}{name}")
    return tuple(files), max(offset, header_end)


def _parse_line_header_v5(
    data: bytes, offset: int, offset_size: int
) -> tuple[tuple[str, ...], int]:
    _unit_length, offset, _dwarf64 = _read_initial_length(data, offset)
    (version,) = struct.unpack_from("<H", data, offset)
    offset += 2
    offset += 4  # header_length (always 4 bytes in DWARF5)
    offset += 1  # address_size
    offset += 1  # segment_selector_size
    offset += 1  # minimum_instruction_length
    offset += 1  # maximum_operations_per_instruction
    offset += 1  # default_is_stmt
    offset += 1  # line_base
    offset += 1  # line_range
    offset += 1  # opcode_base
    opcode_base = data[offset - 1]
    offset += opcode_base - 1  # standard_opcode_lengths

    directories: list[str] = []
    dir_count, offset = _read_uleb(data, offset)
    format_count = data[offset]
    offset += 1
    formats: list[tuple[int, int]] = []
    for _ in range(format_count):
        content_type, offset = _read_uleb(data, offset)
        form, offset = _read_uleb(data, offset)
        formats.append((content_type, form))
    for _ in range(dir_count):
        parts: dict[int, object] = {}
        for content_type, form in formats:
            parts[content_type], offset = _read_form_value(
                data, offset, form, offset_size, 5, b"", b"", 0
            )
        directories.append(str(parts.get(1, "")))

    files: list[str] = []
    file_count, offset = _read_uleb(data, offset)
    format_count = data[offset]
    offset += 1
    formats = []
    for _ in range(format_count):
        content_type, offset = _read_uleb(data, offset)
        form, offset = _read_uleb(data, offset)
        formats.append((content_type, form))
    for _ in range(file_count):
        parts = {}
        for content_type, form in formats:
            parts[content_type], offset = _read_form_value(
                data, offset, form, offset_size, 5, b"", b"", 0
            )
        name = str(parts.get(1, ""))
        dir_index = parts.get(2, 0)
        prefix = ""
        if isinstance(dir_index, int) and 0 < dir_index <= len(directories):
            prefix = directories[dir_index - 1] + "/"
        files.append(f"{prefix}{name}")
    return tuple(files), offset


def _read_initial_length(data: bytes, offset: int) -> tuple[int, int, bool]:
    """Read a unit length; returns ``(length, next_offset, is_dwarf64)``."""
    (length,) = struct.unpack_from("<I", data, offset)
    offset += 4
    if length == 0xFFFFFFFF:
        (length,) = struct.unpack_from("<Q", data, offset)
        offset += 8
        return length, offset, True
    return length, offset, False


# --- form values -------------------------------------------------------------


def _read_form_value(
    data: bytes,
    offset: int,
    form: int,
    offset_size: int,
    version: int,
    debug_str: bytes,
    debug_line_str: bytes,
    implicit_const: int,
    address_size: int = 8,
) -> tuple[object, int]:
    """Decode one attribute value, returning ``(value, next_offset)``.

    ``offset_size`` is the DWARF format width (4, or 8 for DWARF64);
    ``address_size`` is the compilation unit's target address width and is
    what ``DW_FORM_addr`` encodes.
    """
    if form == DW_FORM_indirect:
        form, offset = _read_uleb(data, offset)
        return _read_form_value(
            data, offset, form, offset_size, version, debug_str,
            debug_line_str, implicit_const, address_size,
        )
    if form == DW_FORM_flag_present:
        return True, offset
    if form == DW_FORM_implicit_const:
        return implicit_const, offset
    if form == DW_FORM_data1:
        return data[offset], offset + 1
    if form == DW_FORM_data2:
        return struct.unpack_from("<H", data, offset)[0], offset + 2
    if form == DW_FORM_data4:
        return struct.unpack_from("<I", data, offset)[0], offset + 4
    if form == DW_FORM_data8:
        return struct.unpack_from("<Q", data, offset)[0], offset + 8
    if form == DW_FORM_data16:
        return bytes(data[offset : offset + 16]), offset + 16
    if form == DW_FORM_sdata:
        return _read_sleb(data, offset)
    if form == DW_FORM_udata:
        return _read_uleb(data, offset)
    if form == DW_FORM_string:
        return _read_cstr(data, offset)
    if form == DW_FORM_strp:
        (str_offset,) = struct.unpack_from("<I" if offset_size == 4 else "<Q", data, offset)
        offset += offset_size
        return _string_at(debug_str, str_offset), offset
    if form == DW_FORM_line_strp:
        (str_offset,) = struct.unpack_from("<I" if offset_size == 4 else "<Q", data, offset)
        offset += offset_size
        return _string_at(debug_line_str, str_offset), offset
    if form == DW_FORM_addr:
        return (
            int.from_bytes(data[offset : offset + address_size], "little"),
            offset + address_size,
        )
    if form == DW_FORM_ref_addr:
        size = offset_size if version >= 5 else 4
        return int.from_bytes(data[offset : offset + size], "little"), offset + size
    if form == DW_FORM_ref1:
        return data[offset], offset + 1
    if form == DW_FORM_ref2:
        return struct.unpack_from("<H", data, offset)[0], offset + 2
    if form == DW_FORM_ref4:
        return struct.unpack_from("<I", data, offset)[0], offset + 4
    if form == DW_FORM_ref8:
        return struct.unpack_from("<Q", data, offset)[0], offset + 8
    if form == DW_FORM_ref_udata:
        return _read_uleb(data, offset)
    if form == DW_FORM_sec_offset:
        size = offset_size
        return int.from_bytes(data[offset : offset + size], "little"), offset + size
    if form == DW_FORM_block1:
        length = data[offset]
        offset += 1
        return bytes(data[offset : offset + length]), offset + length
    if form == DW_FORM_block2:
        (length,) = struct.unpack_from("<H", data, offset)
        offset += 2
        return bytes(data[offset : offset + length]), offset + length
    if form == DW_FORM_block4:
        (length,) = struct.unpack_from("<I", data, offset)
        offset += 4
        return bytes(data[offset : offset + length]), offset + length
    if form == DW_FORM_block:
        length, offset = _read_uleb(data, offset)
        return bytes(data[offset : offset + length]), offset + length
    if form == DW_FORM_exprloc:
        length, offset = _read_uleb(data, offset)
        return bytes(data[offset : offset + length]), offset + length
    if form == DW_FORM_flag:
        return bool(data[offset]), offset + 1
    if form == DW_FORM_strx:
        index, offset = _read_uleb(data, offset)
        return index, offset
    if form == DW_FORM_strx1:
        return data[offset], offset + 1
    if form == DW_FORM_strx2:
        return struct.unpack_from("<H", data, offset)[0], offset + 2
    if form == DW_FORM_strx3:
        return int.from_bytes(data[offset : offset + 3], "little"), offset + 3
    if form == DW_FORM_strx4:
        return struct.unpack_from("<I", data, offset)[0], offset + 4
    if form == DW_FORM_addrx:
        index, offset = _read_uleb(data, offset)
        return index, offset
    if form in (DW_FORM_addrx1,):
        return data[offset], offset + 1
    if form in (DW_FORM_addrx2,):
        return struct.unpack_from("<H", data, offset)[0], offset + 2
    if form in (DW_FORM_addrx3,):
        return int.from_bytes(data[offset : offset + 3], "little"), offset + 3
    if form in (DW_FORM_addrx4,):
        return struct.unpack_from("<I", data, offset)[0], offset + 4
    raise DwarfFormatError(f"unsupported DWARF form 0x{form:x}")


def _string_at(table: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("utf-8", errors="replace")


# --- compilation units and DIEs ----------------------------------------------


def _parse_dies(
    data: bytes,
    offset: int,
    abbreviations: dict[int, _Abbrev],
    offset_size: int,
    version: int,
    debug_str: bytes,
    debug_line_str: bytes,
    budget: list[int],
    address_size: int = 8,
    limit: int | None = None,
    depth: int = 0,
    parent_die: "_Die | None" = None,
) -> tuple[tuple[_Die, ...], int]:
    """Parse a sibling list of DIEs; returns ``(dies, next_offset)``.

    ``limit`` bounds the compilation unit: the top-level sibling list ends at
    the unit boundary rather than at a null DIE, so reading past it must stop
    instead of raising.
    """
    dies: list[_Die] = []
    while True:
        if limit is not None and offset >= limit:
            break
        die_offset = offset
        code, offset = _read_uleb(data, offset)
        if code == 0:
            break  # end of this sibling list
        abbrev = abbreviations.get(code)
        if abbrev is None:
            raise DwarfFormatError(f"unknown abbreviation code {code}")
        attributes: list[_Attribute] = []
        for name, form, implicit in abbrev.attributes:
            value, offset = _read_form_value(
                data, offset, form, offset_size, version,
                debug_str, debug_line_str, implicit, address_size,
            )
            attributes.append(_Attribute(name=name, value=value))
        die = _Die(
            offset=die_offset,
            tag=abbrev.tag,
            attributes=tuple(attributes),
            children=(),
            parent=parent_die,
        )
        dies.append(die)
        if abbrev.has_children:
            budget[0] -= 1
            if budget[0] < 0 or depth > 64:
                raise DwarfFormatError("DIE tree too large")
            # The DIE must exist before recursing so its children can point
            # back at it; enclosing namespaces depend on that link.
            children, offset = _parse_dies(
                data, offset, abbreviations, offset_size, version,
                debug_str, debug_line_str, budget, address_size, limit,
                depth + 1, die,
            )
            die.children = children
    return tuple(dies), offset


def _parse_units(
    info: bytes,
    abbrev_data: bytes,
    debug_str: bytes,
    debug_line_str: bytes,
    line_data: bytes,
) -> list[_Unit]:
    units: list[_Unit] = []
    offset = 0
    budget = [_MAX_DIES]
    while offset + 12 <= len(info):
        unit_offset = offset
        unit_length, cursor, dwarf64 = _read_initial_length(info, offset)
        unit_end = cursor + unit_length
        if unit_end > len(info) or unit_length < 4:
            break
        offset_size = 8 if dwarf64 else 4
        (version,) = struct.unpack_from("<H", info, cursor)
        cursor += 2
        # DWARF 2-4: version, debug_abbrev_offset, address_size.
        # DWARF 5:   version, unit_type, address_size, debug_abbrev_offset.
        unit_type = None
        if version >= 5:
            unit_type = info[cursor]
            cursor += 1
            address_size = info[cursor]
            cursor += 1
            (abbrev_offset,) = struct.unpack_from(
                "<I" if offset_size == 4 else "<Q", info, cursor
            )
            cursor += offset_size
            if unit_type in (0x04, 0x05, 0x06):
                cursor += 8  # dwo id
        else:
            (abbrev_offset,) = struct.unpack_from(
                "<I" if offset_size == 4 else "<Q", info, cursor
            )
            cursor += offset_size
            address_size = info[cursor]
            cursor += 1
        try:
            abbreviations = _parse_abbreviations(abbrev_data, abbrev_offset)
            dies, _cursor = _parse_dies(
                info, cursor, abbreviations, offset_size, version,
                debug_str, debug_line_str, budget, address_size, unit_end,
            )
        except (DwarfFormatError, IndexError, struct.error):
            offset = unit_end
            continue

        line_files: tuple[str, ...] = ()
        cu = dies[0] if dies and dies[0].tag == DW_TAG_compile_unit else None
        if cu is not None:
            stmt_list = cu.get(DW_AT_stmt_list)
            if isinstance(stmt_list, int) and line_data:
                line_files, _ = _parse_line_file_names(
                    line_data, stmt_list, version, offset_size
                )
        units.append(
            _Unit(
                offset=unit_offset,
                version=version,
                offset_size=offset_size,
                dies=dies,
                line_files=line_files,
            )
        )
        offset = unit_end
    return units


# --- type resolution ---------------------------------------------------------


_POINTER_TAGS = {
    DW_TAG_pointer_type: "*",
    DW_TAG_reference_type: "&",
}


_QUALIFIER_TAGS = {
    DW_TAG_const_type: " const",
    DW_TAG_volatile_type: " volatile",
    DW_TAG_restrict_type: " restrict",
}

_ANONYMOUS_TAGS = {
    DW_TAG_structure_type: "struct",
    DW_TAG_class_type: "class",
    DW_TAG_union_type: "union",
    DW_TAG_enumeration_type: "enum",
}


def _type_name(
    reference: object,
    dies_by_offset: dict[int, _Die],
    unit_offset: int,
    depth: int = 0,
) -> str | None:
    """Resolve a ``DW_AT_type`` reference to a readable type name."""
    if not isinstance(reference, int) or depth > _MAX_TYPE_DEPTH:
        return None
    die = dies_by_offset.get(unit_offset + reference)
    if die is None:
        return None
    name = die.get(DW_AT_name)
    if isinstance(name, str) and name:
        return name
    if die.tag in _POINTER_TAGS or die.tag in _QUALIFIER_TAGS:
        inner = _type_name(die.get(DW_AT_type), dies_by_offset, unit_offset, depth + 1)
        if inner is None:
            return None
        suffix = _POINTER_TAGS.get(die.tag) or _QUALIFIER_TAGS[die.tag]
        return f"{inner}{suffix}"
    if die.tag in _ANONYMOUS_TAGS:
        return f"{_ANONYMOUS_TAGS[die.tag]} <anonymous>"
    if die.tag == DW_TAG_array_type:
        inner = _type_name(die.get(DW_AT_type), dies_by_offset, unit_offset, depth + 1)
        return f"{inner}[]" if inner else "[]"
    if die.tag == DW_TAG_subroutine_type:
        return "function"
    return None


# --- function extraction -----------------------------------------------------


def _walk(dies: tuple[_Die, ...]):
    for die in dies:
        yield die
        yield from _walk(die.children)


def _extract_functions(units: list[_Unit]) -> tuple[DwarfFunction, ...]:
    dies_by_offset: dict[int, _Die] = {}
    for unit in units:
        for die in _walk(unit.dies):
            dies_by_offset.setdefault(die.offset, die)

    functions: list[DwarfFunction] = []
    for unit in units:
        for die in _walk(unit.dies):
            if die.tag != DW_TAG_subprogram:
                continue
            name, linkage_name = _function_names(die, dies_by_offset, unit.offset)
            if not name and not linkage_name:
                continue
            qualified = _qualified_function_name(die, name)
            parameters: list[DwarfParameter] = []
            for child in die.children_with_tag(DW_TAG_formal_parameter):
                param_name = child.get(DW_AT_name)
                param_type = _type_name(
                    child.get(DW_AT_type), dies_by_offset, unit.offset
                )
                origin = child.get(DW_AT_abstract_origin)
                if not isinstance(param_name, str) and isinstance(origin, int):
                    origin_die = dies_by_offset.get(unit.offset + origin)
                    if origin_die is not None:
                        param_name = origin_die.get(DW_AT_name)
                        if param_type is None:
                            param_type = _type_name(
                                origin_die.get(DW_AT_type),
                                dies_by_offset,
                                unit.offset,
                            )
                if param_name is None and param_type is None:
                    continue
                parameters.append(
                    DwarfParameter(
                        name=param_name if isinstance(param_name, str) else "",
                        type_name=param_type,
                    )
                )
            unit_name = ""
            if unit.dies and isinstance(unit.dies[0].get(DW_AT_name), str):
                unit_name = unit.dies[0].get(DW_AT_name)
            functions.append(
                DwarfFunction(
                    name=qualified,
                    linkage_name=linkage_name,
                    low_pc=die.get(DW_AT_low_pc),
                    high_pc=die.get(DW_AT_high_pc),
                    return_type=_type_name(
                        die.get(DW_AT_type), dies_by_offset, unit.offset
                    ),
                    decl_file=_decl_file(die, unit),
                    decl_line=die.get(DW_AT_decl_line),
                    parameters=tuple(parameters),
                    unit_name=unit_name,
                )
            )
    return tuple(functions)


def _qualified_function_name(die: _Die, name: str) -> str:
    """Qualify a function name with its enclosing namespaces and classes."""
    if not name or "::" in name:
        return name
    enclosing = die.enclosing_names()
    return "::".join((*enclosing, name)) if enclosing else name


def _function_names(
    die: _Die, dies_by_offset: dict[int, _Die], unit_offset: int
) -> tuple[str, str]:
    """Read DW_AT_name / DW_AT_linkage_name, following specification links."""
    name = die.get(DW_AT_name)
    linkage = die.get(DW_AT_linkage_name)
    for attribute in (DW_AT_specification, DW_AT_abstract_origin):
        if isinstance(name, str) and isinstance(linkage, str):
            break
        reference = die.get(attribute)
        if not isinstance(reference, int):
            continue
        target = dies_by_offset.get(unit_offset + reference)
        if target is None:
            continue
        if not isinstance(name, str):
            name = target.get(DW_AT_name)
        if not isinstance(linkage, str):
            linkage = target.get(DW_AT_linkage_name)
    return (
        name if isinstance(name, str) else "",
        linkage if isinstance(linkage, str) else "",
    )


def _decl_file(die: _Die, unit: _Unit) -> str | None:
    value = die.get(DW_AT_decl_file)
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        if 0 < value <= len(unit.line_files):
            return unit.line_files[value - 1]
        return f"<file#{value}>"
    return None


# --- public API --------------------------------------------------------------


def parse_dwarf(path: Path) -> DwarfInfo:
    """Parse debug information from the ELF image at ``path``.

    Raises:
        ElfFormatError: the target is not a parseable ELF image.
    """
    elf = parse_elf(path)
    info_section = elf.section(".debug_info")
    if info_section is None or not info_section.size:
        return DwarfInfo(has_debug_info=False)

    data = _read_section(path, info_section.offset, info_section.size)
    debug_str = _read_optional(path, elf, ".debug_str")
    debug_line_str = _read_optional(path, elf, ".debug_line_str")
    line_data = _read_optional(path, elf, ".debug_line")
    abbrev_data = _read_optional(path, elf, ".debug_abbrev")

    units = _parse_units(data, abbrev_data, debug_str, debug_line_str, line_data)
    functions = _extract_functions(units)
    return DwarfInfo(
        functions=functions,
        units=tuple(
            unit.dies[0].get(DW_AT_name)
            for unit in units
            if unit.dies and isinstance(unit.dies[0].get(DW_AT_name), str)
        ),
        version=units[0].version if units else None,
        has_debug_info=True,
    )


def _read_section(path: Path, offset: int, size: int) -> bytes:
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(size)


def _read_optional(path: Path, elf, name: str) -> bytes:
    section = elf.section(name)
    if section is None or not section.size:
        return b""
    return _read_section(path, section.offset, section.size)
