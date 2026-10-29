"""Hand-built ELF64 fixtures shared by the dynamic-linking tests.

The images are assembled from literal offsets rather than by a real
toolchain, so every value a test asserts on is visible in the test itself.
"""

import struct

SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_TEXTREL = 22
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27

PF_X, PF_W, PF_R = 1, 2, 4
PT_LOAD, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK = 1, 2, 0x6474E552, 0x6474E551


def build_elf(sections, *, machine=62, phdrs=(), entry=0x1000):
    """Build an ELF64 little-endian image from a list of section dicts.

    A section dict carries ``name``, ``type``, ``flags``, ``addr``, ``data``
    and optionally ``link``, ``info`` and ``entsize``.  Program headers are
    given as ``(type, flags, vaddr, filesz, memsz)`` tuples and are placed
    over the first loadable segment.
    """
    shstrtab = bytearray(b"\x00")
    name_offsets: dict[bytes, int] = {b"": 0}
    for section in list(sections) + [{"name": ".shstrtab", "type": SHT_STRTAB}]:
        raw = section["name"].encode()
        if raw not in name_offsets:
            name_offsets[raw] = len(shstrtab)
            shstrtab.extend(raw + b"\x00")
    shstrtab_bytes = bytes(shstrtab)

    # Section index 0 is the reserved null section every ELF image carries.
    everything = [
        {
            "name": "",
            "type": 0,
            "flags": 0,
            "addr": 0,
            "data": b"",
            "align": 0,
        }
    ] + list(sections) + [
        {
            "name": ".shstrtab",
            "type": SHT_STRTAB,
            "flags": 0,
            "addr": 0,
            "data": shstrtab_bytes,
        }
    ]

    phnum = len(phdrs)
    phoff = 64 if phnum else 0
    body_start = 64 + phnum * 56

    body = bytearray()
    placed = []
    for section in everything:
        blob = section.get("data", b"")
        offset = body_start + len(body)
        body.extend(blob)
        if len(body) % 8:
            body.extend(b"\x00" * (8 - len(body) % 8))
        placed.append((section, offset, len(blob)))

    shoff = body_start + len(body)
    header = (
        b"\x7fELF"
        + bytes([2, 1, 1])
        + bytes(9)
        + (3).to_bytes(2, "little")          # e_type DYN
        + machine.to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + entry.to_bytes(8, "little")
        + phoff.to_bytes(8, "little")
        + shoff.to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + phnum.to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + len(placed).to_bytes(2, "little")
        + (len(placed) - 1).to_bytes(2, "little")
    )

    program_header_bytes = b""
    for p_type, p_flags, vaddr, filesz, memsz in phdrs:
        program_header_bytes += (
            p_type.to_bytes(4, "little")
            + p_flags.to_bytes(4, "little")
            + body_start.to_bytes(8, "little")
            + vaddr.to_bytes(8, "little")
            + vaddr.to_bytes(8, "little")
            + filesz.to_bytes(8, "little")
            + memsz.to_bytes(8, "little")
            + (0x1000).to_bytes(8, "little")
        )

    section_header_bytes = b""
    for section, offset, size in placed:
        section_header_bytes += (
            name_offsets[section["name"].encode()].to_bytes(4, "little")
            + section["type"].to_bytes(4, "little")
            + section.get("flags", 0).to_bytes(8, "little")
            + section.get("addr", 0).to_bytes(8, "little")
            + offset.to_bytes(8, "little")
            + size.to_bytes(8, "little")
            + section.get("link", 0).to_bytes(4, "little")
            + section.get("info", 0).to_bytes(4, "little")
            + section.get("align", 8).to_bytes(8, "little")
            + section.get("entsize", 0).to_bytes(8, "little")
        )

    return header + program_header_bytes + bytes(body) + section_header_bytes


def make_dynstr(entries):
    """A dynamic string table plus the offset of every entry."""
    blob = bytearray(b"\x00")
    offsets = {}
    for entry in entries:
        offsets[entry] = len(blob)
        blob.extend(entry.encode() + b"\x00")
    return bytes(blob), offsets


def make_dynsym(names, name_offsets):
    """A dynamic symbol table; index 0 is the reserved null entry."""
    blob = b""
    for name, shndx, value in [("", 0, 0), *names]:
        blob += (
            name_offsets.get(name, 0).to_bytes(4, "little")   # st_name
            + bytes([1, 0])                                   # st_info, st_other
            + shndx.to_bytes(2, "little")                      # st_shndx
            + value.to_bytes(8, "little")                      # st_value
            + (0).to_bytes(8, "little")                        # st_size
        )
    return blob


def dynamic_image(
    *,
    needed=("libc.so",),
    soname=None,
    rpath=None,
    runpath=None,
    flags=None,
    flags_1=None,
    textrel=False,
    extra_sections=(),
    dynsym_names=(),
    rela_entries=(),
    phdrs=(),
    init_array=None,
    versioned_names=(),
    needed_file=None,
    version_name=None,
):
    """An image with a ``.dynamic`` table describing the requested facts."""
    strtab_entries = list(needed)
    if soname:
        strtab_entries.append(soname)
    if rpath:
        strtab_entries.append(rpath)
    if runpath:
        strtab_entries.append(runpath)
    strtab_entries.extend(name for name, _shndx, _value in dynsym_names)
    strtab_entries.extend(versioned_names)
    if needed_file:
        strtab_entries.append(needed_file)
    if version_name:
        strtab_entries.append(version_name)
    dynstr, offsets = make_dynstr(strtab_entries)

    dynsym = make_dynsym(dynsym_names, offsets) if dynsym_names else b""

    rela = b""
    for r_offset, symbol_index, r_type in rela_entries:
        rela += struct.pack("<QQq", r_offset, symbol_index << 32 | r_type, 0)

    # Section addresses are fixed so the dynamic table can point at them.
    dynstr_addr = 0x3000
    dynsym_addr = 0x3100
    dynamic_addr = 0x3200
    rela_addr = 0x3300

    entries = []
    entries.append((DT_NEEDED, offsets[needed[0]]) if needed else (DT_NULL, 0))
    for name in needed[1:]:
        entries.append((DT_NEEDED, offsets[name]))
    if soname:
        entries.append((DT_SONAME, offsets[soname]))
    if rpath:
        entries.append((DT_RPATH, offsets[rpath]))
    if runpath:
        entries.append((DT_RUNPATH, offsets[runpath]))
    entries.append((DT_STRTAB, dynstr_addr))
    if dynsym:
        entries.append((DT_SYMTAB, dynsym_addr))
    if init_array:
        entries.append((DT_INIT_ARRAY, init_array[0]))
        entries.append((DT_INIT_ARRAYSZ, init_array[1]))
    if flags is not None:
        entries.append((DT_FLAGS, flags))
    if flags_1 is not None:
        entries.append((DT_FLAGS_1, flags_1))
    if textrel:
        entries.append((DT_TEXTREL, 0))
    entries.append((DT_NULL, 0))

    dynamic = b"".join(
        tag.to_bytes(8, "little", signed=True) + value.to_bytes(8, "little")
        for tag, value in entries
    )

    sections = [
        {
            "name": ".text",
            "type": SHT_PROGBITS,
            "flags": PF_R | PF_X,
            "addr": 0x1000,
            "data": b"\x90" * 16,
        },
        {
            "name": ".dynstr",
            "type": SHT_STRTAB,
            "flags": PF_R | PF_W,
            "addr": dynstr_addr,
            "data": dynstr,
        },
        {
            "name": ".dynsym",
            "type": SHT_DYNSYM,
            "flags": PF_R | PF_W,
            "addr": dynsym_addr,
            "data": dynsym,
            "link": 2,
            "info": 1,
            "entsize": 24,
        },
        {
            "name": ".dynamic",
            "type": SHT_DYNAMIC,
            "flags": PF_R | PF_W,
            "addr": dynamic_addr,
            "data": dynamic,
            "link": 2,
            "entsize": 16,
        },
    ]
    if rela:
        sections.append(
            {
                "name": ".rela.dyn",
                "type": SHT_RELA,
                "flags": PF_R,
                "addr": rela_addr,
                "data": rela,
                "link": 3,
                "entsize": 24,
            }
        )
    if init_array:
        sections.append(
            {
                "name": ".init_array",
                "type": SHT_PROGBITS,
                "flags": PF_R | PF_W,
                "addr": init_array[0],
                "data": (0x1234).to_bytes(8, "little")
                * (init_array[1] // 8),
            }
        )
    sections.extend(
        version_sections(
            dynstr,
            offsets,
            versioned_names=versioned_names,
            needed_file=needed_file,
            version_name=version_name,
        )
    )
    sections.extend(extra_sections)
    if not phdrs:
        phdrs = ((PT_LOAD, PF_R | PF_X, 0x1000, 0x1000, 0x1000),)
    return build_elf(sections, phdrs=phdrs)




def version_sections(
    dynstr, offsets, *, versioned_names=(), needed_file=None, version_name=None
):
    """The ``.gnu.version*`` sections describing symbol versioning."""
    sections = []

    if versioned_names:
        # One base definition (index 1) and one real version (index 2).
        definitions = b""
        entries = (
            (1, versioned_names[0], True),
            (2, versioned_names[1], False),
        )
        for position, (index, name, is_base) in enumerate(entries):
            # vd_next points at the next definition; the last one ends the
            # chain with zero.
            vd_next = 0 if position == len(entries) - 1 else 28
            definitions += (
                (1).to_bytes(2, "little")          # vd_version
                + ((1 if is_base else 0)).to_bytes(2, "little")  # vd_flags
                + index.to_bytes(2, "little")       # vd_ndx
                + (1).to_bytes(2, "little")         # vd_cnt
                + (0).to_bytes(4, "little")         # vd_hash
                + (20).to_bytes(4, "little")        # vd_aux
                + vd_next.to_bytes(4, "little")     # vd_next
                + offsets[name].to_bytes(4, "little")  # vda_name
                + (0).to_bytes(4, "little")         # vda_next
            )
        sections.append(
            {
                "name": ".gnu.version_d",
                "type": SHT_GNU_VERDEF,
                "flags": 0,
                "addr": 0,
                "data": definitions,
                "link": 2,
                "entsize": 0,
            }
        )
        # Every dynamic symbol carries a version index.
        versym = b"".join(
            index.to_bytes(2, "little") for index in (1, 2, 2)
        )
        sections.append(
            {
                "name": ".gnu.version",
                "type": SHT_GNU_VERSYM,
                "flags": 0,
                "addr": 0,
                "data": versym,
                "link": 3,
                "entsize": 2,
            }
        )

    if needed_file:
        requirements = (
            (1).to_bytes(2, "little")              # vn_version
            + (1).to_bytes(2, "little")            # vn_cnt
            + offsets[needed_file].to_bytes(4, "little")   # vn_file
            + (16).to_bytes(4, "little")           # vn_aux
            + (0).to_bytes(4, "little")            # vn_next
            + (0).to_bytes(4, "little")            # vna_hash
            + (0).to_bytes(2, "little")            # vna_flags
            + (2).to_bytes(2, "little")            # vna_other
            + offsets[version_name].to_bytes(4, "little")   # vna_name
            + (0).to_bytes(4, "little")            # vna_next
        )
        sections.append(
            {
                "name": ".gnu.version_r",
                "type": SHT_GNU_VERNEED,
                "flags": 0,
                "addr": 0,
                "data": requirements,
                "link": 2,
                "entsize": 0,
            }
        )
    return sections
