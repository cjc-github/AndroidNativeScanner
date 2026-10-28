"""DWARF parser edge cases: specification chains and DWARF5 line tables."""

import struct

from conftest import build_elf64_with_dwarf

from soinsight.infrastructure.dwarf import parse_dwarf
from soinsight.infrastructure.dwarf.parser import _string_at


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _wrap_v4_line_table(directory: bytes, file_name: bytes) -> bytes:
    line_body = bytearray()
    line_body += struct.pack("<H", 4)          # version
    line_body += struct.pack("<I", 0)          # header_length placeholder
    header_start = len(line_body)
    line_body += bytes([1, 1, 1, 0xFB, 14, 13])
    line_body += bytes(12)                     # standard_opcode_lengths
    line_body += directory + b"\x00\x00"       # directories, empty-terminated
    line_body += file_name + b"\x00" + _uleb(1) + _uleb(0) + _uleb(0)
    line_body += b"\x00"                       # end of file_names
    struct.pack_into("<I", line_body, 2, len(line_body) - header_start)
    return struct.pack("<I", len(line_body)) + bytes(line_body)


def test_string_at_reads_offset_zero():
    """A string table may legitimately start at offset 0."""
    assert _string_at(b"abc\x00def", 0) == "abc"
    assert _string_at(b"abc\x00def", 4) == "def"
    assert _string_at(b"", 0) == ""
    assert _string_at(b"abc", 10) == ""


def test_definition_inherits_declaration_attributes(tmp_path):
    """An out-of-class definition merges with its specification DIE.

    The declaration carries the qualified name, linkage name, virtuality and
    declaration position; the definition carries the code address. Both DIEs
    describe one function, so exactly one record must survive.
    """
    DW_AT_specification = 0x47
    DW_AT_virtuality = 0x4C

    abbrev = bytearray()
    # 1: compile_unit (children)
    abbrev += _uleb(1) + _uleb(0x11) + bytes([1])
    abbrev += _uleb(0x03) + _uleb(0x08)        # name, string
    abbrev += _uleb(0x1B) + _uleb(0x08)        # comp_dir, string
    abbrev += _uleb(0x10) + _uleb(0x17)        # stmt_list, sec_offset
    abbrev += _uleb(0) + _uleb(0)
    # 2: class_type (children)
    abbrev += _uleb(2) + _uleb(0x02) + bytes([1])
    abbrev += _uleb(0x03) + _uleb(0x08)
    abbrev += _uleb(0) + _uleb(0)
    # 3: subprogram declaration (no children)
    abbrev += _uleb(3) + _uleb(0x2E) + bytes([0])
    abbrev += _uleb(0x03) + _uleb(0x08)        # name
    abbrev += _uleb(0x6E) + _uleb(0x08)        # linkage_name
    abbrev += _uleb(0x3A) + _uleb(0x0B)        # decl_file
    abbrev += _uleb(0x3B) + _uleb(0x0B)        # decl_line
    abbrev += _uleb(DW_AT_virtuality) + _uleb(0x0B)
    abbrev += _uleb(0) + _uleb(0)
    # 4: subprogram definition (no children)
    abbrev += _uleb(4) + _uleb(0x2E) + bytes([0])
    abbrev += _uleb(DW_AT_specification) + _uleb(0x13)   # specification, ref4
    abbrev += _uleb(0x6E) + _uleb(0x08)        # linkage_name
    abbrev += _uleb(0x11) + _uleb(0x01)        # low_pc, addr
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(0)

    cu_die = _uleb(1) + b"spec.cpp\x00" + b"/work\x00" + struct.pack("<I", 0)
    die_base = 4 + 2 + 4 + 1 + len(cu_die)

    body = bytearray()
    body += _uleb(2) + b"Base\x00"             # class_type
    decl_ref = die_base + len(body)
    body += _uleb(3)
    body += b"compute\x00" + b"_ZN4demo4Base7computeEi\x00"
    body += bytes([1, 7, 1])                   # file 1, line 7, virtuality 1
    body += _uleb(0)                           # end of class children
    body += _uleb(4) + struct.pack("<I", decl_ref)
    body += b"_ZN4demo4Base7computeEi\x00"
    body += struct.pack("<Q", 0x1000)
    body += _uleb(0)                           # end of CU children

    cu_body = bytearray()
    cu_body += struct.pack("<H", 4)
    cu_body += struct.pack("<I", 0)
    cu_body += bytes([8])
    cu_body += cu_die + bytes(body)
    debug_info = struct.pack("<I", len(cu_body)) + bytes(cu_body)

    sample = tmp_path / "libspec.so"
    sample.write_bytes(
        build_elf64_with_dwarf(
            {
                ".debug_abbrev": bytes(abbrev),
                ".debug_info": debug_info,
                ".debug_line": _wrap_v4_line_table(b"/work", b"spec.cpp"),
            }
        )
    )

    info = parse_dwarf(sample)

    assert len(info.functions) == 1
    function = info.functions[0]
    assert function.name == "Base::compute"
    assert function.linkage_name == "_ZN4demo4Base7computeEi"
    assert function.virtual is True
    assert function.low_pc == 0x1000
    assert function.decl_file == "/work/spec.cpp"
    assert function.decl_line == 7


def test_dwarf5_line_table_resolves_declaration_files(tmp_path):
    """DWARF5 line tables use format tables, line_strp and 0-based indices."""
    DW_FORM_line_strp = 0x1F
    DW_LNCT_path = 0x1
    DW_LNCT_directory_index = 0x2

    abbrev = bytearray()
    # 1: compile_unit (children)
    abbrev += _uleb(1) + _uleb(0x11) + bytes([1])
    abbrev += _uleb(0x03) + _uleb(DW_FORM_line_strp)      # name
    abbrev += _uleb(0x10) + _uleb(0x17)                   # stmt_list
    abbrev += _uleb(0) + _uleb(0)
    # 2: subprogram (no children)
    abbrev += _uleb(2) + _uleb(0x2E) + bytes([0])
    abbrev += _uleb(0x03) + _uleb(DW_FORM_line_strp)      # name
    abbrev += _uleb(0x6E) + _uleb(DW_FORM_line_strp)      # linkage_name
    abbrev += _uleb(0x3A) + _uleb(0x0B)                   # decl_file (0-based)
    abbrev += _uleb(0x3B) + _uleb(0x0B)                   # decl_line
    abbrev += _uleb(0x11) + _uleb(0x01)                   # low_pc
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(0)

    debug_line_str = (
        b"/work\x00five.cpp\x00five\x00_ZN4demo4Base7computeEi\x00"
    )
    cu_die = _uleb(1) + struct.pack("<I", 6) + struct.pack("<I", 0)
    die_base = 4 + 2 + 1 + 1 + 4 + len(cu_die)

    body = bytearray()
    body += _uleb(2)
    body += struct.pack("<I", 15) + struct.pack("<I", 20)   # name, linkage_name
    body += bytes([0, 3])                     # decl_file 0, decl_line 3
    body += struct.pack("<Q", 0x1000)
    body += _uleb(0)

    cu_body = bytearray()
    cu_body += struct.pack("<H", 5)           # version 5
    cu_body += bytes([0x01])                  # unit_type: DW_UT_compile
    cu_body += bytes([8])                     # address_size
    cu_body += struct.pack("<I", 0)           # debug_abbrev_offset
    cu_body += cu_die + bytes(body)
    debug_info = struct.pack("<I", len(cu_body)) + bytes(cu_body)

    line_body = bytearray()
    line_body += struct.pack("<H", 5)         # version
    line_body += struct.pack("<I", 0)         # header_length placeholder
    header_start = len(line_body)
    line_body += bytes([8, 0, 1, 1, 1, 0xFB, 14, 13])
    line_body += bytes(12)                    # standard_opcode_lengths
    # directory table
    line_body += bytes([1])                   # directory_entry_format_count
    line_body += _uleb(DW_LNCT_path) + _uleb(DW_FORM_line_strp)
    line_body += _uleb(1)                     # directories_count
    line_body += struct.pack("<I", 0)         # dir[0] = "/work"
    # file table
    line_body += bytes([2])                   # file_name_entry_format_count
    line_body += _uleb(DW_LNCT_path) + _uleb(DW_FORM_line_strp)
    line_body += _uleb(DW_LNCT_directory_index) + _uleb(0x0F)
    line_body += _uleb(1)                     # file_names_count
    line_body += struct.pack("<I", 6) + _uleb(0)
    struct.pack_into("<I", line_body, 2, len(line_body) - header_start)
    debug_line = struct.pack("<I", len(line_body)) + bytes(line_body)

    sample = tmp_path / "libfive.so"
    sample.write_bytes(
        build_elf64_with_dwarf(
            {
                ".debug_abbrev": bytes(abbrev),
                ".debug_info": debug_info,
                ".debug_line": debug_line,
                ".debug_line_str": debug_line_str,
            }
        )
    )

    info = parse_dwarf(sample)

    assert len(info.functions) == 1
    function = info.functions[0]
    assert function.name == "five"
    assert function.linkage_name == "_ZN4demo4Base7computeEi"
    # DWARF5 decl_file indices are 0-based: file 0 resolves directly.
    assert function.decl_file == "/work/five.cpp"
    assert function.decl_line == 3
    assert function.low_pc == 0x1000
