"""Build test images carrying a JNI ``RegisterNatives`` array.

The layout mirrors a real position-independent shared object: the method array
sits in a writable allocated section with one load-time relocation per pointer
slot, the name and signature strings live in ``.rodata``, and the registered
functions are real ``.text`` bytes with symbol-table entries.

Three relocation shapes occur in the wild and all are covered here:

* RELA with ``R_X86_64_RELATIVE`` -- the addend carries the address, which is
  what a 64-bit image emits;
* REL with ``R_ARM_RELATIVE`` -- 32-bit ARM keeps the value inline in the
  section and the relocation entry has no addend at all;
* ``R_ARM_ABS32`` against a symbol -- 32-bit ARM names the function pointer
  by symbol, so the slot ends up holding ``symbol + addend``.
"""

import struct

from elf_builder import (
    SHT_DYNSYM,
    SHT_PROGBITS,
    SHT_RELA,
    SHT_REL,
    SHT_STRTAB,
    build_elf,
    make_dynstr,
)

# x86-64: the addend carries the address.
R_RELATIVE = 8
# 32-bit ARM: the value lives inline, and a function pointer may be named
# by symbol instead.
R_ARM_RELATIVE = 23
R_ARM_ABS32 = 2

TEXT_ADDR = 0x1000
RODATA_ADDR = 0x2000
DATA_REL_RO_ADDR = 0x3000

ON_LOAD_ADDR = TEXT_ADDR
NAMED_FN_ADDR = TEXT_ADDR + 0x40
STRIPPED_FN_ADDR = TEXT_ADDR + 0x80

_TEXT_SHNDX = 1  # null section first, then .text as index 1.


def _cstr(text: str) -> bytes:
    return text.encode("utf-8") + b"\x00"


def _rela(slot: int, target: int) -> bytes:
    return struct.pack("<QQq", slot, R_RELATIVE, target)


def _make_func_dynsym(entries, offsets):
    """A dynamic symbol table whose defined entries are GLOBAL FUNC.

    ``make_dynsym`` marks everything LOCAL OBJECT, which the parser correctly
    reports as data; a native-method table needs real function symbols.
    """
    blob = b""
    for name, shndx, value in [("", 0, 0), *entries]:
        info = 0x12  # bind GLOBAL | type FUNC
        blob += (
            offsets.get(name, 0).to_bytes(4, "little")
            + bytes([info, 0])
            + shndx.to_bytes(2, "little")
            + value.to_bytes(8, "little")
            + (0x20 if value > 0 else 0).to_bytes(8, "little")
        )
    return blob


def _assemble(
    entries,
    *,
    with_on_load,
    with_import,
    named,
    relocation_shape="rela-relative",
):
    """Shared builder: sections, relocations and the dynamic symbol table."""
    strings = b""
    string_addr = {}
    for name, signature, _ in entries:
        for text in (name, signature):
            if text not in string_addr:
                string_addr[text] = RODATA_ADDR + len(strings)
                strings += _cstr(text)

    dyn_names = []
    if with_on_load:
        dyn_names.append(("JNI_OnLoad", _TEXT_SHNDX, ON_LOAD_ADDR))
    if with_import:
        dyn_names.append(("RegisterNatives", 0, 0))
    for address, symbol in sorted(named.items()):
        dyn_names.append((symbol, _TEXT_SHNDX, address))

    if relocation_shape == "rela-relative":
        data_rel_ro = b"\x00" * (8 * 3 * len(entries))
        rela = b""
        for index, (name, signature, function_address) in enumerate(entries):
            for field, target in (
                (0, string_addr[name]),
                (1, string_addr[signature]),
                (2, function_address),
            ):
                slot = DATA_REL_RO_ADDR + 8 * (3 * index + field)
                rela += _rela(slot, target)
        reloc_section = {
            "name": ".rela.dyn",
            "type": SHT_RELA,
            "flags": 0x40,
            "addr": 0x4000,
            "data": rela,
            "link": 5,
            "entsize": 24,
        }
    else:
        # An SHT_REL image: the entry has no addend, so the value the loader
        # writes is stored inline at the slot.
        data_rel_ro = bytearray(8 * 3 * len(entries))
        rel = b""
        for index, (name, signature, function_address) in enumerate(entries):
            for field, target in (
                (0, string_addr[name]),
                (1, string_addr[signature]),
                (2, function_address),
            ):
                slot = DATA_REL_RO_ADDR + 8 * (3 * index + field)
                offset_in_data = slot - DATA_REL_RO_ADDR
                if relocation_shape == "rel-relative" or field != 2:
                    # The name and the signature are plain addresses.
                    rel += struct.pack("<QQ", slot, R_ARM_RELATIVE)
                    data_rel_ro[offset_in_data : offset_in_data + 8] = struct.pack(
                        "<Q", target
                    )
                else:
                    # The function pointer is named by symbol: the inline
                    # value is only the addend.
                    symbol_index = 0
                    for name_index, (_sym_name, _shndx, value) in enumerate(dyn_names):
                        if value == function_address:
                            symbol_index = name_index + 1
                            break
                    rel += struct.pack("<QQ", slot, (symbol_index << 32) | R_ARM_ABS32)
                    data_rel_ro[offset_in_data : offset_in_data + 8] = struct.pack(
                        "<Q", 0
                    )
        reloc_section = {
            "name": ".rel.dyn",
            "type": SHT_REL,
            "flags": 0x42,
            "addr": 0x4000,
            "data": rel,
            "link": 5,
            "entsize": 16,
        }

    text = b"\x55\x48\x89\xe5\xc3" * 0x100  # 1280 bytes: room for every entry

    dynstr, offsets = make_dynstr([name for name, _, _ in dyn_names])
    dynsym = _make_func_dynsym(dyn_names, offsets)

    sections = [
        {"name": ".text", "type": SHT_PROGBITS, "flags": 0x6, "addr": TEXT_ADDR, "data": text},
        {"name": ".rodata", "type": SHT_PROGBITS, "flags": 0x2, "addr": RODATA_ADDR, "data": strings},
        {
            "name": ".data.rel.ro",
            "type": SHT_PROGBITS,
            "flags": 0x3,
            "addr": DATA_REL_RO_ADDR,
            "data": bytes(data_rel_ro),
        },
        reloc_section,
        {"name": ".dynstr", "type": SHT_STRTAB, "flags": 0, "addr": 0x5000, "data": dynstr},
        {
            "name": ".dynsym",
            "type": SHT_DYNSYM,
            "flags": 0x2,
            "addr": 0x5100,
            "data": dynsym,
            "link": 5,
            "entsize": 24,
        },
    ]
    return build_elf(sections)


def build_jni_image(
    entries,
    *,
    with_on_load=True,
    with_register_natives_import=True,
    named_functions=None,
    relocation_shape="rela-relative",
):
    """An image whose array entries all resolve back to named symbols."""
    named = dict(named_functions or {})
    for index, (_name, _signature, function_address) in enumerate(entries):
        if function_address not in named:
            named[function_address] = f"native_{index}"
    return _assemble(
        entries,
        with_on_load=with_on_load,
        with_import=with_register_natives_import,
        named=named,
        relocation_shape=relocation_shape,
    )


def build_stripped_jni_image(entries):
    """A variant whose registered functions have no symbol names at all."""
    return _assemble(
        entries,
        with_on_load=True,
        with_import=True,
        named={ON_LOAD_ADDR: "JNI_OnLoad"},
    )
