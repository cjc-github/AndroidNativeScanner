"""Load-time relocations.

The dynamic linker patches an image in memory before the first instruction
runs.  Every patch is recorded in a ``.rela.*`` / ``.rel.*`` table, and those
tables are the authoritative statement of which symbols the image needs and
where each one is written.

The parser is deliberately conservative: a relocation whose target section
cannot be identified is still reported, but its symbol stays unresolved
rather than being guessed from a neighbouring index.
"""

from __future__ import annotations

import struct

from . import constants as elf
from .structures import Relocation, SectionHeader, Symbol

SHT_RELA = 4
SHT_REL = 9

# The relocation types that matter most when describing a shared object:
# a data pointer to an external symbol, a call-site slot, and the
# loader-relative fixups that a position-independent image is full of.
_RELOCATION_NAMES = {
    6: "GLOB_DAT",
    7: "JUMP_SLOT",
    8: "RELATIVE",
    10: "32",
    11: "32S",
    21: "64",
    22: "PC32",
    23: "GOT32",
    24: "PLT32",
    25: "COPY",
    26: "GLOB_DAT64",
    37: "IRELATIVE",
    1027: "RELATIVE",
    1026: "GLOB_DAT",
    1025: "JUMP_SLOT",
}


def parse_relocations(
    data,
    *,
    prefix: str,
    is64: bool,
    sections: tuple[SectionHeader, ...],
    dynsym: tuple[Symbol, ...] = (),
) -> tuple[Relocation, ...]:
    """Decode every relocation table of the image.

    ``prefix`` is the struct format character for the image endianness and
    ``is64`` its ELF class.  ``dynsym`` resolves the symbol indexes the
    tables refer to; an index outside that table stays unresolved.
    """
    relocations: list[Relocation] = []
    for section in sections:
        if section.type_value not in (SHT_RELA, SHT_REL) or section.size <= 0:
            continue
        relocations.extend(
            _parse_section(data, prefix, is64, section, dynsym)
        )
    return tuple(relocations)


def _parse_section(
    data,
    prefix: str,
    is64: bool,
    section: SectionHeader,
    dynsym: tuple[Symbol, ...],
) -> tuple[Relocation, ...]:
    """Decode one ``.rela``/``.rel`` section."""
    is_rela = section.type_value == SHT_RELA
    default_size = (24 if is64 else 12) if is_rela else (16 if is64 else 8)
    entry_size = section.entry_size or default_size
    if entry_size <= 0:
        return ()
    count = section.size // entry_size
    start = section.offset
    end = start + count * entry_size
    if start < 0 or end > len(data):
        return ()

    entries: list[Relocation] = []
    for index in range(count):
        base = start + index * entry_size
        if is64:
            offset, info = struct.unpack_from(prefix + "QQ", data, base)[:2]
            symbol_index = info >> 32
            relocation_type = info & 0xFFFFFFFF
            addend = 0
            if is_rela and base + 24 <= len(data):
                (addend,) = struct.unpack_from(prefix + "q", data, base + 16)
        else:
            offset, info = struct.unpack_from(prefix + "II", data, base)
            symbol_index = info >> 8
            relocation_type = info & 0xFF
            addend = 0
            if is_rela and base + 12 <= len(data):
                (addend,) = struct.unpack_from(prefix + "i", data, base + 8)
        entries.append(
            Relocation(
                section=section.name,
                offset=offset,
                symbol_index=symbol_index,
                symbol_name=_symbol_name(dynsym, symbol_index),
                type=relocation_type,
                addend=addend,
                kind="rela" if is_rela else "rel",
            )
        )
    return tuple(entries)


def _symbol_name(dynsym: tuple[Symbol, ...], index: int) -> str | None:
    """The name a relocation's symbol index refers to, if it has one."""
    if index <= 0 or index >= len(dynsym):
        return None
    name = dynsym[index].name
    return name or None


def relocation_type_name(relocation_type: int) -> str:
    """A readable name for a relocation type, when one is well known."""
    return _RELOCATION_NAMES.get(relocation_type, str(relocation_type))
