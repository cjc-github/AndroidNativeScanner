"""Unit tests for the pure-Python ELF parser."""

from pathlib import Path

import pytest

from soinsight.infrastructure.elf import ElfFormatError, parse_bytes, parse_elf


def _all_unknown_hardening() -> dict:
    return {
        "has_gnu_relro": None,
        "executable_stack": None,
        "has_stack_canary": None,
        "has_cfi": None,
        "has_pac": None,
    }


def _write(tmp_path: Path, data: bytes, name: str = "libsample.so") -> Path:
    sample = tmp_path / name
    sample.write_bytes(data)
    return sample


def test_parse_bytes_rejects_non_elf():
    with pytest.raises(ElfFormatError, match="magic"):
        parse_bytes(b"not an elf file at all")


def test_parse_bytes_rejects_empty_input():
    with pytest.raises(ElfFormatError):
        parse_bytes(b"")


def test_parse_bytes_rejects_truncated_header():
    """A valid ident with a short body is not a parseable ELF image."""
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    with pytest.raises(ElfFormatError, match="truncated"):
        parse_bytes(ident + bytes(20))


def test_parse_bytes_rejects_unknown_class():
    header = bytearray(b"\x7fELF" + bytes(12))
    header[4] = 9
    with pytest.raises(ElfFormatError, match="class"):
        parse_bytes(bytes(header) + bytes(64))


def test_parse_elf_accepts_header_only_image(tmp_path, minimal_elf64_little):
    """A declared-but-absent section table means "unknown", not "invalid"."""
    elf = parse_elf(_write(tmp_path, minimal_elf64_little))

    assert elf.header.elf_class == "ELF64"
    assert elf.header.type == "DYN"
    assert elf.header.machine == "x86-64"
    assert elf.sections == ()
    assert elf.symbols == ()
    assert elf.is_stripped is True
    assert elf.hardening_facts() == _all_unknown_hardening()


def test_parse_elf_reads_program_headers(tmp_path):
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)

    def phdr(p_type: int, p_flags: int) -> bytes:
        return p_type.to_bytes(4, "little") + p_flags.to_bytes(4, "little") + bytes(48)

    phdrs = [phdr(0x6474E551, 0x7), phdr(0x6474E552, 0x4)]
    header = (
        (3).to_bytes(2, "little")
        + (62).to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (0x401000).to_bytes(8, "little")
        + (64).to_bytes(8, "little")   # e_phoff
        + (0).to_bytes(8, "little")    # e_shoff
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + len(phdrs).to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
    )
    elf = parse_elf(_write(tmp_path, ident + header + b"".join(phdrs)))

    assert [program_header.type for program_header in elf.program_headers] == [
        "GNU_STACK",
        "GNU_RELRO",
    ]
    assert elf.hardening_facts() == {
        "has_gnu_relro": True,
        "executable_stack": True,
        "has_stack_canary": None,
        "has_cfi": None,
        "has_pac": None,
    }


def test_parse_elf_reports_unknown_hardening_when_phdrs_truncated(tmp_path):
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    phdr = (0x6474E551).to_bytes(4, "little") + (4).to_bytes(4, "little") + bytes(48)
    header = (
        (3).to_bytes(2, "little")
        + (62).to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (0x401000).to_bytes(8, "little")
        + (64).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
    )
    elf = parse_elf(_write(tmp_path, ident + header + phdr[:6]))

    assert elf.program_headers == ()
    assert elf.hardening_facts() == _all_unknown_hardening()


def test_parse_elf_reads_sections_and_symbols(tmp_path, elf64_with_symbols):
    elf = parse_elf(_write(tmp_path, elf64_with_symbols))

    section_names = [section.name for section in elf.sections]
    assert section_names == [
        "", ".text", ".data", ".dynsym", ".dynstr", ".symtab", ".strtab", ".shstrtab",
    ]
    assert elf.is_stripped is False
    assert set(elf.symbol_tables) == {".dynsym", ".symtab"}

    dynamic = elf.symbols_from(".dynsym")
    assert [symbol.name for symbol in dynamic] == [
        "",
        "Java_com_example_Foo_nativeInit",
        "Java_com_example_Foo_nativeInit__ILjava_lang_String_2",
        "_ZN3foo3barEi",
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "_ZN7android7IBinderD2Ev",
        "printf",
        "g_counter",
    ]

    export = dynamic[1]
    assert (export.bind, export.type, export.visibility) == ("GLOBAL", "FUNC", "DEFAULT")
    assert export.is_defined is True
    assert export.is_exported is True
    assert export.is_function is True
    assert (export.value, export.size) == (0x1000, 0x40)

    imported = dynamic[6]
    assert imported.is_defined is False
    assert imported.is_exported is False


def test_parse_elf_marks_stripped_image(tmp_path, elf64_stripped_symbols):
    elf = parse_elf(_write(tmp_path, elf64_stripped_symbols))

    assert elf.is_stripped is True
    assert elf.symbol_tables == (".dynsym",)
    assert elf.symbols_from(".symtab") == ()
    assert len(elf.symbols_from(".dynsym")) == 8


def test_parse_elf_ignores_symbol_table_past_end_of_file(tmp_path, elf64_with_symbols):
    """A symbol table declared beyond EOF degrades to "no symbols"."""
    import struct

    image = bytearray(elf64_with_symbols)
    # Corrupt .dynsym's sh_offset to point past the end of the file.
    shoff = struct.unpack_from("<Q", image, 0x28)[0]
    # Section index 3 is .dynsym; sh_offset lives at +0x18 within the entry.
    struct.pack_into("<Q", image, shoff + 3 * 64 + 0x18, len(image) + 4096)
    elf = parse_elf(_write(tmp_path, bytes(image)))

    assert elf.symbols_from(".dynsym") == ()
    # The regular symbol table is untouched and still decodes.
    assert len(elf.symbols_from(".symtab")) == 8


def test_parse_elf_reads_elf32_image(tmp_path):
    """ELF32 little-endian images decode with the 32-bit layout."""
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = (
        (3).to_bytes(2, "little")
        + (3).to_bytes(2, "little")     # EM_386
        + (1).to_bytes(4, "little")
        + (0x8048000).to_bytes(4, "little")
        + (52).to_bytes(4, "little")    # e_phoff
        + (0).to_bytes(4, "little")     # e_shoff
        + (0).to_bytes(4, "little")
        + (52).to_bytes(2, "little")
        + (32).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (40).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
    )
    elf = parse_elf(_write(tmp_path, ident + header))

    assert elf.header.elf_class == "ELF32"
    assert elf.header.is_64bit is False
    assert elf.header.machine == "x86"


def _gnu_property_aarch64_note(mask: int) -> bytes:
    """Build a ``.note.gnu.property`` owning an AArch64 feature-1 property."""
    import struct

    feature = (
        struct.pack("<II", 0xC0000000, 4)  # GNU_PROPERTY_AARCH64_FEATURE_1_AND
        + struct.pack("<I", mask)
    )
    # GNU_PROPERTY_TYPE_0 (0) terminates the descriptor.
    descriptor = feature + struct.pack("<II", 0, 0)
    header = struct.pack("<III", 4, len(descriptor), 0)  # namesz, descsz, type
    return header + b"GNU\x00" + descriptor


def _elf_with_symbols(names_with_extra, *, note_mask=None):
    from tests.conftest import build_elf64_with_symbols

    extras = None
    if note_mask is not None:
        extras = {".note.gnu.property": (7, _gnu_property_aarch64_note(note_mask))}
    symbols = [("", 0, 3, 0xFFF1, 0, 0), ("printf", 1, 0, 0, 0, 0)]
    symbols.extend(
        (name, 1, 2, 0, 0, 0) for name in names_with_extra  # undefined FUNC
    )
    return build_elf64_with_symbols(symbols, extra_sections=extras)


def test_hardening_reports_missing_canary_no_symbols(tmp_path):
    from tests.conftest import build_elf64_with_symbols

    elf = parse_elf(_write(tmp_path, build_elf64_with_symbols([])))
    assert elf.hardening_facts()["has_stack_canary"] is None


def test_hardening_detects_stack_canary(tmp_path):
    elf = parse_elf(_write(tmp_path, _elf_with_symbols(["__stack_chk_fail"])))
    assert elf.hardening_facts()["has_stack_canary"] is True


def test_hardening_detects_cfi(tmp_path):
    elf = parse_elf(_write(tmp_path, _elf_with_symbols(["__cfi_slowpath"])))
    assert elf.hardening_facts()["has_cfi"] is True


def test_hardening_pac_unknown_without_property_note(tmp_path):
    elf = parse_elf(_write(tmp_path, _elf_with_symbols([])))
    assert elf.hardening_facts()["has_pac"] is None


def test_hardening_detects_pac_from_gnu_property(tmp_path):
    elf = parse_elf(_write(tmp_path, _elf_with_symbols([], note_mask=0x02)))
    assert elf.hardening_facts()["has_pac"] is True


def test_hardening_distinguishes_bti_without_pac(tmp_path):
    elf = parse_elf(_write(tmp_path, _elf_with_symbols([], note_mask=0x01)))
    assert elf.hardening_facts()["has_pac"] is False
