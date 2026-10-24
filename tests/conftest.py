"""Shared pytest fixtures for SOInsight tests."""

import struct

import pytest


def _cstr(text: str) -> bytes:
    return text.encode() + b"\x00"


def build_elf64_with_symbols(symbols, *, with_symtab: bool = True) -> bytes:
    """Build a minimal ELF64 little-endian image carrying symbol tables.

    ``symbols`` is a sequence of ``(name, bind, type, shndx, value, size)``
    tuples, where ``bind``/``type`` use the raw ``STB_*``/``STT_*`` values and
    ``shndx`` is the 1-based section index (0 means undefined).
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
    for name in (".text", ".data", ".dynsym", ".dynstr", ".symtab", ".strtab", ".shstrtab"):
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
