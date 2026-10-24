"""Shared pytest fixtures for SOInsight tests."""

import struct

import pytest

def _cstr(text: str) -> bytes:
    return text.encode() + b"\x00"


def build_elf64_with_symbols(
    symbols, *, with_symtab: bool = True, extra_sections: dict[str, bytes] | None = None
) -> bytes:
    """Build a minimal ELF64 little-endian image carrying symbol tables.

    ``symbols`` is a sequence of ``(name, bind, type, shndx, value, size)``
    tuples, where ``bind``/``type`` use the raw ``STB_*``/``STT_*`` values and
    ``shndx`` is the 1-based section index (0 means undefined).

    ``extra_sections`` appends arbitrary named sections, which is how debug
    information is attached to the same image.
    """
    dynstr = bytearray(b"\x00")
    dynstr_offsets: dict[str, int] = {}
    for name, *_ in symbols:
        if name and name not in dynstr_offsets:
            dynstr_offsets[name] = len(dynstr)
            dynstr.extend(_cstr(name))

    strtab = bytearray(b"\x00")
    strtab_offsets: dict[str, int] = {}
    for name, *_ in symbols:
        if name and name not in strtab_offsets:
            strtab_offsets[name] = len(strtab)
            strtab.extend(_cstr(name))

    def encode(offsets: dict[str, int]) -> bytes:
        out = bytearray()
        for name, bind, type_, shndx, value, size in symbols:
            out.extend(
                struct.pack(
                    "<IBBHQQ",
                    offsets.get(name, 0),
                    (bind << 4) | type_,
                    0,  # st_other: STV_DEFAULT
                    shndx,
                    value,
                    size,
                )
            )
        return bytes(out)

    dynsym = encode(dynstr_offsets)
    symtab = encode(strtab_offsets) if with_symtab else b""

    shstrtab = bytearray(b"\x00")
    names: dict[str, int] = {}
    extra_names = list(extra_sections) if extra_sections else []
    for name in (
        [".text", ".data", ".dynsym", ".dynstr", ".symtab", ".strtab"]
        + extra_names
        + [".shstrtab"]
    ):
        if name not in names:
            names[name] = len(shstrtab)
            shstrtab.extend(_cstr(name))
    shstrtab_bytes = bytes(shstrtab)

    SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM = 1, 2, 3, 11
    sections = [
        ("", 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (".text", SHT_PROGBITS, 0x6, 0x1000, 0, 0x100, 0, 0, 16, 0),
        (".data", SHT_PROGBITS, 0x3, 0x2000, 0, 8, 0, 0, 8, 0),
        (".dynsym", SHT_DYNSYM, 0x2, 0, 0, len(dynsym), 4, 1, 8, 24),
        (".dynstr", SHT_STRTAB, 0x2, 0, 0, len(dynstr), 0, 0, 1, 0),
    ]
    if with_symtab:
        sections.append((".symtab", SHT_SYMTAB, 0, 0, 0, len(symtab), 6, 1, 8, 24))
        sections.append((".strtab", SHT_STRTAB, 0, 0, 0, len(strtab), 0, 0, 1, 0))
    if extra_sections:
        for name, blob in extra_sections.items():
            sections.append((name, SHT_PROGBITS, 0, 0, 0, len(blob), 0, 0, 1, 0))
    sections.append((".shstrtab", SHT_STRTAB, 0, 0, 0, len(shstrtab_bytes), 0, 0, 1, 0))
    shstrndx = len(sections) - 1

    body = bytearray()

    def place(blob: bytes) -> int:
        offset = 64 + len(body)
        body.extend(blob)
        return offset

    # Placement is keyed by section name so that dropping the regular symbol
    # table does not shift the offsets of the sections that remain.
    placement = {
        ".text": place(b"\x90" * 0x100),
        ".data": place(b"\x00" * 8),
        ".dynsym": place(dynsym),
        ".dynstr": place(dynstr),
    }
    if with_symtab:
        placement[".symtab"] = place(symtab)
        placement[".strtab"] = place(strtab)
    if extra_sections:
        for name, blob in extra_sections.items():
            placement[name] = place(blob)
    placement[".shstrtab"] = place(shstrtab_bytes)

    section_table = bytearray()
    for name, type_, flags, addr, _, size, link, info, align, entsize in sections:
        section_table.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                names.get(name, 0), type_, flags, addr, placement.get(name, 0), size,
                link, info, align, entsize,
            )
        )

    image = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    image.extend(
        struct.pack(
            "<HHIQQQIHHHHHH",
            3,        # e_type: ET_DYN
            62,       # e_machine: EM_X86_64
            1,        # e_version
            0x1040,   # e_entry
            0,        # e_phoff
            64 + len(body),  # e_shoff
            0,        # e_flags
            64,       # e_ehsize
            0, 0,     # e_phentsize, e_phnum
            64,       # e_shentsize
            len(sections),  # e_shnum
            shstrndx,       # e_shstrndx
        )
    )
    assert len(image) == 64
    image.extend(body)
    image.extend(section_table)
    return bytes(image)


@pytest.fixture
def minimal_elf64_little() -> bytes:
    """A 64-byte minimal ELF64 little-endian header (type DYN, x86-64)."""
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = (
        (3).to_bytes(2, "little")
        + (62).to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (0x401000).to_bytes(8, "little")
        + (64).to_bytes(8, "little")
        + (1024).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + (8).to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + (12).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
    )
    return ident + header


# Exported functions of a realistic mixed-language shared object: two JNI
# entry points (one plain, one overloaded), C++ methods with Itanium-mangled
# names, an imported function and an exported data object.
SAMPLE_SYMBOLS = [
    ("", 0, 3, 0xFFF1, 0, 0),                                     # STT_SECTION
    ("Java_com_example_Foo_nativeInit", 1, 2, 1, 0x1000, 0x40),
    ("Java_com_example_Foo_nativeInit__ILjava_lang_String_2", 1, 2, 1, 0x1040, 0x30),
    ("_ZN3foo3barEi", 1, 2, 1, 0x1080, 0x20),
    ("_ZNSt6vectorIiSaIiEE9push_backERKi", 1, 2, 1, 0x10A0, 0x60),
    ("_ZN7android7IBinderD2Ev", 1, 2, 1, 0x1100, 0x18),
    ("printf", 1, 0, 0, 0, 0),
    ("g_counter", 1, 1, 2, 0x2000, 8),
]


@pytest.fixture
def elf64_with_symbols() -> bytes:
    """A minimal ELF64 image whose symbol tables hold SAMPLE_SYMBOLS."""
    return build_elf64_with_symbols(SAMPLE_SYMBOLS)


@pytest.fixture
def elf64_stripped_symbols() -> bytes:
    """The same image without a regular symbol table (stripped)."""
    return build_elf64_with_symbols(SAMPLE_SYMBOLS, with_symtab=False)


# --- DWARF -------------------------------------------------------------------

DW_TAG_compile_unit = 0x11
DW_TAG_base_type = 0x24
DW_TAG_pointer_type = 0x0F
DW_TAG_const_type = 0x38
DW_TAG_subprogram = 0x2E
DW_TAG_formal_parameter = 0x05
DW_TAG_class_type = 0x02

DW_AT_name = 0x03
DW_AT_byte_size = 0x0B
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_comp_dir = 0x1B
DW_AT_type = 0x49
DW_AT_linkage_name = 0x6E
DW_AT_decl_file = 0x58
DW_AT_decl_line = 0x59

DW_FORM_addr = 0x01
DW_FORM_data1 = 0x0B
DW_FORM_string = 0x08
DW_FORM_ref4 = 0x13
DW_FORM_sec_offset = 0x17


def _dwarf_uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dwarf_sections() -> dict[str, bytes]:
    """Build DWARF 4 debug sections describing two functions.

    ``add`` is a plain C function and ``process`` is a C++ method with a
    mangled linkage name, a pointer parameter and an unsigned parameter, so
    both the join key and the type shapes are exercised.
    """
    abbrev = bytearray()
    # 1: compile_unit (children)
    abbrev += _dwarf_uleb(1) + _dwarf_uleb(DW_TAG_compile_unit) + bytes([1])
    abbrev += _dwarf_uleb(DW_AT_name) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(DW_AT_comp_dir) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(DW_AT_stmt_list) + _dwarf_uleb(DW_FORM_sec_offset)
    abbrev += _dwarf_uleb(0) + _dwarf_uleb(0)
    # 2: base_type
    abbrev += _dwarf_uleb(2) + _dwarf_uleb(DW_TAG_base_type) + bytes([0])
    abbrev += _dwarf_uleb(DW_AT_name) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(DW_AT_byte_size) + _dwarf_uleb(DW_FORM_data1)
    abbrev += _dwarf_uleb(0) + _dwarf_uleb(0)
    # 3: pointer_type, 4: const_type
    for code, tag in ((3, DW_TAG_pointer_type), (4, DW_TAG_const_type)):
        abbrev += _dwarf_uleb(code) + _dwarf_uleb(tag) + bytes([0])
        abbrev += _dwarf_uleb(DW_AT_type) + _dwarf_uleb(DW_FORM_ref4)
        abbrev += _dwarf_uleb(0) + _dwarf_uleb(0)
    # 5: subprogram (children), 6: formal_parameter, 7: class_type (children)
    abbrev += _dwarf_uleb(5) + _dwarf_uleb(DW_TAG_subprogram) + bytes([1])
    abbrev += _dwarf_uleb(DW_AT_name) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(DW_AT_linkage_name) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(DW_AT_low_pc) + _dwarf_uleb(DW_FORM_addr)
    abbrev += _dwarf_uleb(DW_AT_decl_file) + _dwarf_uleb(DW_FORM_data1)
    abbrev += _dwarf_uleb(DW_AT_decl_line) + _dwarf_uleb(DW_FORM_data1)
    abbrev += _dwarf_uleb(DW_AT_type) + _dwarf_uleb(DW_FORM_ref4)
    abbrev += _dwarf_uleb(0) + _dwarf_uleb(0)
    abbrev += _dwarf_uleb(6) + _dwarf_uleb(DW_TAG_formal_parameter) + bytes([0])
    abbrev += _dwarf_uleb(DW_AT_name) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(DW_AT_type) + _dwarf_uleb(DW_FORM_ref4)
    abbrev += _dwarf_uleb(0) + _dwarf_uleb(0)
    abbrev += _dwarf_uleb(7) + _dwarf_uleb(DW_TAG_class_type) + bytes([1])
    abbrev += _dwarf_uleb(DW_AT_name) + _dwarf_uleb(DW_FORM_string)
    abbrev += _dwarf_uleb(0) + _dwarf_uleb(0)
    abbrev += _dwarf_uleb(0)  # end of table

    cu_die = (
        _dwarf_uleb(1) + b"sample.c\x00" + b"/work\x00" + struct.pack("<I", 0)
    )
    # DW_FORM_ref4 offsets are relative to the start of the CU header.
    die_base = 4 + 2 + 4 + 1 + len(cu_die)

    body = bytearray()
    int_ref = die_base + len(body)
    body += _dwarf_uleb(2) + b"int\x00" + bytes([4])
    char_ref = die_base + len(body)
    body += _dwarf_uleb(2) + b"char\x00" + bytes([1])
    const_char_ref = die_base + len(body)
    body += _dwarf_uleb(4) + struct.pack("<I", char_ref)
    char_ptr_ref = die_base + len(body)
    body += _dwarf_uleb(3) + struct.pack("<I", const_char_ref)
    uint_ref = die_base + len(body)
    body += _dwarf_uleb(2) + b"unsigned int\x00" + bytes([4])

    # int add(int a, int b)
    body += _dwarf_uleb(5) + b"add\x00" + b"add\x00"
    body += struct.pack("<Q", 0x1000)
    body += bytes([1, 3]) + struct.pack("<I", int_ref)
    body += _dwarf_uleb(6) + b"a\x00" + struct.pack("<I", int_ref)
    body += _dwarf_uleb(6) + b"b\x00" + struct.pack("<I", int_ref)
    body += _dwarf_uleb(0)

    # int MyClass::process(char const* buffer, unsigned int length)
    body += _dwarf_uleb(7) + b"MyClass\x00"
    body += _dwarf_uleb(5)
    body += b"process\x00" + b"_ZN7MyClass7processEPKci\x00"
    body += struct.pack("<Q", 0x1100)
    body += bytes([1, 7]) + struct.pack("<I", int_ref)
    body += _dwarf_uleb(6) + b"buffer\x00" + struct.pack("<I", char_ptr_ref)
    body += _dwarf_uleb(6) + b"length\x00" + struct.pack("<I", uint_ref)
    body += _dwarf_uleb(0)
    body += _dwarf_uleb(0)  # end of class_type children

    body += _dwarf_uleb(0)  # end of CU children

    cu_body = bytearray()
    cu_body += struct.pack("<H", 4)      # DWARF version
    cu_body += struct.pack("<I", 0)      # debug_abbrev_offset
    cu_body += bytes([8])                # address_size
    cu_body += cu_die + bytes(body)
    debug_info = struct.pack("<I", len(cu_body)) + bytes(cu_body)

    # .debug_line header (DWARF 4) with one directory and one file.
    line_body = bytearray()
    line_body += struct.pack("<H", 4)
    line_body += struct.pack("<I", 0)    # header_length placeholder
    header_start = len(line_body)
    line_body += bytes([1])              # minimum_instruction_length
    line_body += bytes([1])              # maximum_operations_per_instruction
    line_body += bytes([1])              # default_is_stmt
    line_body += bytes([0xFB])           # line_base = -5
    line_body += bytes([14])             # line_range
    line_body += bytes([13])             # opcode_base
    line_body += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    line_body += b"/work\x00\x00"        # include_directories
    line_body += b"sample.c\x00" + _dwarf_uleb(1) + _dwarf_uleb(0) + _dwarf_uleb(0)
    line_body += b"\x00"                 # end of file_names
    line_body += b"\x00"                 # end of line program
    struct.pack_into("<I", line_body, 4, len(line_body) - header_start)
    debug_line = struct.pack("<I", len(line_body)) + bytes(line_body)

    return {
        ".debug_abbrev": bytes(abbrev),
        ".debug_info": debug_info,
        ".debug_line": debug_line,
    }


def build_elf64_with_dwarf(sections: dict[str, bytes]) -> bytes:
    """Wrap arbitrary sections in a minimal ELF64 container."""
    shstrtab = bytearray(b"\x00")
    names: dict[str, int] = {}
    for name in list(sections) + [".text", ".shstrtab"]:
        names[name] = len(shstrtab)
        shstrtab.extend(name.encode() + b"\x00")
    shstrtab_bytes = bytes(shstrtab)

    body = bytearray()

    def place(blob: bytes) -> int:
        offset = 64 + len(body)
        body.extend(blob)
        return offset

    blobs = {".text": b"\x90" * 0x100}
    blobs.update(sections)
    blobs[".shstrtab"] = shstrtab_bytes
    placements = {name: place(blob) for name, blob in blobs.items()}

    ordered = list(blobs)
    sh_table = bytearray()
    for name in ordered:
        blob = blobs[name]
        sh_type = 1 if name == ".text" else 3  # PROGBITS / STRTAB
        sh_table += struct.pack(
            "<IIQQQQIIQQ",
            names[name], sh_type, 0, 0, placements[name], len(blob),
            0, 0, 1, 0,
        )
    image = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    image += struct.pack(
        "<HHIQQQIHHHHHH",
        3, 62, 1, 0x1040, 0, 64 + len(body), 0,
        64, 0, 0, 64, len(ordered), len(ordered) - 1,
    )
    image += body
    image += sh_table
    return bytes(image)


@pytest.fixture
def elf64_with_dwarf() -> bytes:
    """A minimal ELF64 image carrying valid DWARF 4 debug information."""
    return build_elf64_with_dwarf(build_dwarf_sections())
