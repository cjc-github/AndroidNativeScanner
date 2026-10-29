"""Tests for the ``basic.xref`` string cross-reference analyzer."""

import struct

import pytest

from elf_builder import SHT_PROGBITS, SHT_STRTAB, build_elf
from soinsight.analyzers.disasm import BasicDisasmAnalyzer
from soinsight.analyzers.xref import BasicXrefAnalyzer
from soinsight.core.analyzer.context import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget

EM_386 = 3
EM_X86_64 = 62
EM_ARM = 40
EM_AARCH64 = 183
EM_RISCV = 243

TEXT_ADDR = 0x1000
RODATA_ADDR = 0x2000

SHT_SYMTAB = 2

# Section attribute flags (not to be confused with the program header flags).
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Capstone is an optional dependency: decoding tests are skipped when it is
# absent, while the string-table and degradation tests still run.
try:
    import capstone
except ImportError:  # pragma: no cover - depends on the environment
    capstone = None

requires_capstone = pytest.mark.skipif(
    capstone is None, reason="capstone is not installed"
)


class _Config:
    """Minimal analysis configuration with optional capability options."""

    def __init__(self, options: dict | None = None) -> None:
        self.extra = {"capability_options": options or {}}


def _target(path) -> AnalysisTarget:
    return AnalysisTarget(
        path=path,
        real_path=path,
        name=path.name,
        size=path.stat().st_size,
        sha256="",
    )


def _make_symtab(entries, name_offsets):
    """Build an ELF64 symbol table; ``entries`` are ``(name, value, size)``."""
    blob = b""
    for name, value, size in entries:
        blob += (
            name_offsets.get(name, 0).to_bytes(4, "little")   # st_name
            + bytes([0x12, 0])                                # GLOBAL FUNC
            + (1).to_bytes(2, "little")                       # st_shndx: .text
            + value.to_bytes(8, "little")                     # st_value
            + size.to_bytes(8, "little")                      # st_size
        )
    return blob


def _make_strtab(names):
    """Build a string table plus the offset of every name."""
    blob = bytearray(b"\x00")
    offsets = {}
    for name in names:
        offsets[name] = len(blob)
        blob.extend(name.encode() + b"\x00")
    return bytes(blob), offsets


def _write_image(
    path,
    *,
    text: bytes = b"",
    rodata: bytes = b"",
    symbols=(),
    machine: int = EM_X86_64,
):
    """Write an ELF64 image with a text, a rodata and a symbol table."""
    strtab, offsets = _make_strtab([name for name, _, _ in symbols])
    sections = [
        {
            "name": ".text",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC | SHF_EXECINSTR,
            "addr": TEXT_ADDR,
            "data": text,
        },
        {
            "name": ".rodata",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC,
            "addr": RODATA_ADDR,
            "data": rodata,
        },
        {
            "name": ".strtab",
            "type": SHT_STRTAB,
            "flags": 0,
            "addr": 0,
            "data": strtab,
        },
        {
            "name": ".symtab",
            "type": SHT_SYMTAB,
            "flags": 0,
            "addr": 0,
            "data": _make_symtab(symbols, offsets),
            "link": 3,
            "info": 1,
            "entsize": 24,
        },
    ]
    path.write_bytes(build_elf(sections, machine=machine))
    return path


def _analyze(path, options: dict | None = None):
    """Run ``basic.disasm`` and ``basic.xref`` over an image."""
    target = _target(path)
    context = AnalysisContext(run_id="test", target=target, config=_Config(options))
    context.add_result(BasicDisasmAnalyzer().analyze(target, context))
    return BasicXrefAnalyzer().analyze(target, context)


def _lea_rip(target_address: int, address: int = TEXT_ADDR) -> bytes:
    """``lea rax, [rip + disp]`` pointing at ``target_address``."""
    displacement = target_address - (address + 7)
    return b"\x48\x8d\x05" + struct.pack("<i", displacement)


def _enc_adrp(rd: int, pc: int, target_page: int) -> bytes:
    """Encode an AArch64 ``adrp`` instruction."""
    offset = (target_page - (pc & ~0xFFF)) >> 12
    immlo = offset & 3
    immhi = (offset >> 2) & 0x7FFFF
    word = (1 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd
    return struct.pack("<I", word)


def _enc_add_imm(rd: int, rn: int, imm: int) -> bytes:
    """Encode an AArch64 ``add rd, rn, #imm`` instruction."""
    word = (1 << 31) | (0b100010 << 23) | (imm << 10) | (rn << 5) | rd
    return struct.pack("<I", word)


def _enc_a64_ldr_ptr(rt: int, rn: int) -> bytes:
    """Encode an AArch64 ``ldr xt, [xn]`` with no displacement."""
    return struct.pack("<I", 0xF9400000 | (rn << 5) | rt)


def _enc_a64_mov_w(rd: int, rn: int) -> bytes:
    """Encode an AArch64 ``mov wd, wn``: a write through the narrow alias."""
    return struct.pack("<I", 0x2A0003E0 | (rn << 16) | rd)


def _enc_a64_cmp_imm(rn: int, imm: int) -> bytes:
    """Encode an AArch64 ``cmp xn, #imm`` (``subs xzr, xn, #imm``)."""
    return struct.pack("<I", 0xF100001F | (imm << 10) | (rn << 5))


def _enc_a64_bl() -> bytes:
    """Encode an AArch64 ``bl`` (zero offset: calls the next instruction)."""
    return struct.pack("<I", 0x94000000)


def _enc_arm_movt(rd: int, imm: int) -> bytes:
    """Encode an ARM ``movt rd, #imm`` (upper 16-bit half immediate)."""
    return struct.pack(
        "<I",
        0xE3400000
        | (((imm >> 12) & 0xF) << 16)
        | (rd << 12)
        | (((imm >> 8) & 0xF) << 8)
        | (imm & 0xFF),
    )


def _enc_a64_ldr(rt: int, rn: int, imm: int) -> bytes:
    """Encode an AArch64 ``ldr xt, [xn, #imm]`` instruction."""
    return struct.pack("<I", 0xF9400000 | (imm << 10) | (rn << 5) | rt)


def _enc_a64_mov(rd: int, rn: int) -> bytes:
    """Encode an AArch64 ``mov xd, xn`` instruction."""
    return struct.pack("<I", 0xAA0003E0 | (rn << 16) | rd)


def _enc_a64_b(pc: int, target: int) -> bytes:
    """Encode an AArch64 ``b`` to ``target``."""
    imm26 = (target - pc) >> 2
    return struct.pack("<I", (0b000101 << 26) | (imm26 & 0x3FFFFFF))


A64_RET = b"\xc0\x03\x5f\xd6"


def _enc_arm_movw(rd: int, imm: int) -> bytes:
    """Encode an ARM ``movw rd, #imm`` (16-bit half immediate)."""
    return struct.pack(
        "<I",
        0xE3000000
        | (((imm >> 12) & 0xF) << 16)
        | (rd << 12)
        | (((imm >> 8) & 0xF) << 8)
        | (imm & 0xFF),
    )


def _enc_arm_movt(rd: int, imm: int) -> bytes:
    """Encode an ARM ``movt rd, #imm`` (upper 16-bit half immediate)."""
    return struct.pack(
        "<I",
        0xE3400000
        | (((imm >> 12) & 0xF) << 16)
        | (rd << 12)
        | (((imm >> 8) & 0xF) << 8)
        | (imm & 0xFF),
    )


def _enc_arm_add_regs(rd: int, rn: int, rm: int) -> bytes:
    """Encode an ARM ``add rd, rn, rm`` (no PC, so no literal-pool form)."""
    return struct.pack("<I", 0xE0800000 | (rd << 12) | (rn << 16) | rm)


def _enc_arm_bl() -> bytes:
    """Encode an ARM ``bl`` (zero offset: calls the next instruction)."""
    return struct.pack("<I", 0xEB000000)


def _enc_arm_ldr(rt: int, rn: int, imm: int) -> bytes:
    """Encode an ARM ``ldr rt, [rn, #imm]`` instruction."""
    return struct.pack("<I", 0xE5900000 | (rn << 16) | (rt << 12) | imm)


def _enc_arm_add_pc(rd: int, rn: int) -> bytes:
    """Encode an ARM ``add rd, pc, rn`` literal-pool form."""
    return struct.pack("<I", 0xE08F0000 | (rd << 12) | rn)


ARM_BX_LR = b"\x1e\xff\x2f\xe1"


@requires_capstone
def test_rip_relative_reference_resolves_to_rodata_string(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR) + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
    )

    result = _analyze(path)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["string"] == "hello world"
    assert xref["string_address"] == hex(RODATA_ADDR)
    assert xref["section"] == ".rodata"
    assert xref["kind"] == "rip-relative"
    assert xref["match"] == "exact"
    assert xref["instruction_address"] == hex(TEXT_ADDR)
    assert xref["function"] == "func"


@requires_capstone
def test_reference_into_the_middle_of_a_string_is_a_suffix_match(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR + 6) + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["string"] == "hello world"
    assert xref["match"] == "suffix"


def test_strings_in_executable_sections_are_ignored(tmp_path):
    """Unwind tables inside ``.text`` look like strings but are not literals."""
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(TEXT_ADDR + 0x20) + b"\xc3" + b"\x00" * 0x1D + b"UAWAVAUATSPH",
        rodata=b"",
        symbols=(("func", TEXT_ADDR, 8),),
    )

    result = _analyze(path)

    assert result.data["string_count"] == 0
    assert result.data["xref_count"] == 0


def test_unallocated_section_strings_are_ignored(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR) + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
    )
    # A section without SHF_ALLOC carries no virtual address, so its bytes
    # cannot be the target of a code reference.
    data = path.read_bytes()
    assert b"hello world" in data

    result = _analyze(path)

    assert result.data["string_count"] == 1


def test_code_without_references_reports_no_xref(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=b"\x90\x90\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 3),),
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0
    assert result.data["referenced_string_count"] == 0
    assert result.data["string_count"] == 1


@requires_capstone
def test_aarch64_adrp_add_pair_resolves_to_the_string(tmp_path):
    text = _enc_adrp(0, TEXT_ADDR, RODATA_ADDR) + _enc_add_imm(0, 0, 0x40)
    text += b"\x60\x00\x00\x14"  # ret
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 12),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["arch"] == "aarch64"
    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["string"] == "hello world"
    assert xref["kind"] == "adrp-add"
    assert xref["match"] == "exact"
    assert xref["function"] == "func"


@requires_capstone
def test_aarch64_register_load_resolves_through_a_tracked_pair(tmp_path):
    """``adrp`` + ``mov`` + ``ldr``: the string is reached through registers."""
    text = (
        _enc_adrp(0, TEXT_ADDR, RODATA_ADDR)
        + _enc_a64_mov(2, 0)
        + _enc_a64_ldr(1, 2, 0x40 // 8)
        + A64_RET
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["string"] == "hello world"
    assert xref["kind"] == "register-load"


@requires_capstone
def test_aarch64_overwritten_page_is_not_reported(tmp_path):
    """A base register reloaded from elsewhere no longer holds the page."""
    text = (
        _enc_adrp(0, TEXT_ADDR, RODATA_ADDR)
        + _enc_a64_ldr_ptr(0, 1)  # x0 = *x1: the tracked page is gone
        + _enc_a64_ldr(1, 0, 0x40 // 8)
        + A64_RET
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


@requires_capstone
def test_aarch64_narrow_write_invalidates_the_wide_page(tmp_path):
    """``mov w0, w1`` writes the same hardware register that holds ``x0``."""
    text = (
        _enc_adrp(0, TEXT_ADDR, RODATA_ADDR)
        + _enc_a64_mov_w(0, 1)
        + _enc_a64_ldr(1, 0, 0x40 // 8)
        + A64_RET
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


@requires_capstone
def test_aarch64_call_drops_a_caller_saved_page(tmp_path):
    """AAPCS64 lets a callee clobber x0-x18, so a page in x0 does not survive."""
    text = (
        _enc_adrp(0, TEXT_ADDR, RODATA_ADDR)
        + _enc_a64_bl()
        + _enc_a64_ldr(1, 0, 0x40 // 8)
        + A64_RET
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


@requires_capstone
def test_aarch64_page_survives_a_call_when_callee_saved(tmp_path):
    """x19 is callee-saved: the same sequence through x19 still resolves."""
    text = (
        _enc_adrp(19, TEXT_ADDR, RODATA_ADDR)
        + _enc_a64_bl()
        + _enc_a64_ldr(1, 19, 0x40 // 8)
        + A64_RET
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    assert result.data["xrefs"][0]["kind"] == "register-load"


@requires_capstone
def test_aarch64_flag_setting_instruction_keeps_the_page(tmp_path):
    """``cmp`` only writes NZCV, so the tracked page must not be dropped."""
    text = (
        _enc_adrp(0, TEXT_ADDR, RODATA_ADDR)
        + _enc_a64_cmp_imm(0, 1)
        + _enc_add_imm(0, 0, 0x40)
        + A64_RET
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 0x40 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    assert result.data["xrefs"][0]["kind"] == "adrp-add"


@requires_capstone
def test_arm_movt_without_movw_does_not_track_a_half_value(tmp_path):
    """The upper half alone is not an address, so no reference is reported."""
    text = (
        _enc_arm_movt(0, RODATA_ADDR >> 16)
        + _enc_arm_ldr(1, 0, 0)
        + ARM_BX_LR
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_ARM,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


@requires_capstone
def test_arm_page_dropped_when_the_base_register_is_rewritten(tmp_path):
    """``add r0, r1, r2`` overwrites the assembled address: no reference."""
    text = (
        _enc_arm_movw(0, RODATA_ADDR & 0xFFFF)
        + _enc_arm_movt(0, RODATA_ADDR >> 16)
        + _enc_arm_add_regs(0, 1, 2)
        + _enc_arm_ldr(1, 0, 0)
        + ARM_BX_LR
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_ARM,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


@requires_capstone
def test_arm_call_drops_a_caller_saved_address(tmp_path):
    """AAPCS lets a callee clobber r0-r3, so an address in r0 does not survive."""
    text = (
        _enc_arm_movw(0, RODATA_ADDR & 0xFFFF)
        + _enc_arm_movt(0, RODATA_ADDR >> 16)
        + _enc_arm_bl()
        + _enc_arm_ldr(1, 0, 0)
        + ARM_BX_LR
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_ARM,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


@requires_capstone
def test_arm_address_survives_a_call_when_callee_saved(tmp_path):
    """r4 is callee-saved: the same sequence assembled into r4 still resolves."""
    text = (
        _enc_arm_movw(4, RODATA_ADDR & 0xFFFF)
        + _enc_arm_movt(4, RODATA_ADDR >> 16)
        + _enc_arm_bl()
        + _enc_arm_ldr(1, 4, 0)
        + ARM_BX_LR
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_ARM,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    assert result.data["xrefs"][0]["kind"] == "register-load"


@requires_capstone
def test_aarch64_branch_target_is_excluded(tmp_path):
    """A ``b`` to a data address is control flow, not a string reference."""
    path = _write_image(
        tmp_path / "sample.so",
        text=_enc_a64_b(TEXT_ADDR, RODATA_ADDR) + A64_RET,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
        machine=EM_AARCH64,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0
    assert result.data["string_count"] == 1


@requires_capstone
def test_arm_movw_movt_pair_reaches_the_string_through_a_register(tmp_path):
    text = (
        _enc_arm_movw(0, RODATA_ADDR & 0xFFFF)
        + _enc_arm_movt(0, RODATA_ADDR >> 16)
        + _enc_arm_ldr(1, 0, 4)
        + ARM_BX_LR
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 4 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_ARM,
    )

    result = _analyze(path)

    assert result.data["arch"] == "arm"
    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["string"] == "hello world"
    assert xref["kind"] == "register-load"
    assert xref["match"] == "exact"


@requires_capstone
def test_arm_literal_pool_reference_resolves(tmp_path):
    """``ldr rt, [pc, #n]`` + ``add rt, pc, rt`` materialises the target."""
    literal = 0x1000  # add at 0x1004: 0x1004 + 8 + 0x1000 == RODATA_ADDR + 12
    text = (
        _enc_arm_ldr(3, 15, 4)
        + _enc_arm_add_pc(3, 3)
        + ARM_BX_LR
        + struct.pack("<I", literal)
    )
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"\x00" * 12 + b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_ARM,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["string"] == "hello world"
    assert xref["kind"] == "literal"
    assert xref["instruction_address"] == hex(TEXT_ADDR + 4)


@requires_capstone
def test_x86_absolute_operand_resolves(tmp_path):
    """32-bit code addresses literals absolutely rather than RIP-relatively."""
    text = b"\xc7\x05" + struct.pack("<I", RODATA_ADDR) + b"\x90\x00\x00\x00"
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, len(text)),),
        machine=EM_386,
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["kind"] == "absolute"
    assert xref["string"] == "hello world"


@requires_capstone
def test_code_outside_any_function_is_still_scanned(tmp_path):
    """Instruction bytes that no symbol covers (PLT stubs) are covered too."""
    lea = _lea_rip(RODATA_ADDR)
    path = _write_image(
        tmp_path / "sample.so",
        text=b"\x90\x90" + lea,
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 2),),
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["function"] is None
    assert xref["instruction_address"] == hex(TEXT_ADDR + 2)


@requires_capstone
def test_extent_beyond_the_section_is_clipped_to_the_region(tmp_path):
    """A symbol size overshooting its section must not decode the next one."""
    string = b"hello world\x00"
    # ``.text`` holds 8 instruction bytes; the symbol claims 64. The first
    # bytes of ``.rodata`` are a second, *data* reference that must not be
    # decoded as an instruction, and must not be counted twice for .text.
    text = _lea_rip(RODATA_ADDR + 8, TEXT_ADDR)
    rodata = _lea_rip(RODATA_ADDR + 8, RODATA_ADDR) + string
    path = _write_image(
        tmp_path / "sample.so",
        text=text,
        rodata=rodata,
        symbols=(("func", TEXT_ADDR, 64),),
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 1
    xref = result.data["xrefs"][0]
    assert xref["instruction_address"] == hex(TEXT_ADDR)


def test_branch_target_is_not_reported_as_a_data_reference(tmp_path):
    """A ``call`` operand points at code, not at a string literal."""
    text = b"\xe8" + struct.pack("<i", RODATA_ADDR - (TEXT_ADDR + 5))
    path = _write_image(
        tmp_path / "sample.so",
        text=text + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 6),),
    )

    result = _analyze(path)

    assert result.data["xref_count"] == 0


def test_unsupported_architecture_reports_a_diagnostic(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR) + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
        machine=EM_RISCV,
    )

    result = _analyze(path)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["xref_count"] == 0
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "XREF_UNSUPPORTED_ARCH" in codes


def test_non_elf_input_fails_with_a_diagnostic(tmp_path):
    path = tmp_path / "not-an-elf.bin"
    path.write_bytes(b"just some text, definitely not an ELF image")

    result = _analyze(path)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


@requires_capstone
def test_xref_list_is_truncated_at_the_configured_limit(tmp_path):
    text = b"".join(_lea_rip(RODATA_ADDR + index) for index in range(4))
    path = _write_image(
        tmp_path / "sample.so",
        text=text + b"\xc3",
        rodata=b"aaaa\x00bbbb\x00cccc\x00dddd\x00",
        symbols=(("func", TEXT_ADDR, len(text) + 1),),
    )

    result = _analyze(path, {"basic.xref": {"max_xrefs": 2}})

    assert result.data["xref_count"] == 2
    assert result.data["truncated"] is True
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "XREF_TRUNCATED" in codes


def test_string_table_is_truncated_at_the_configured_limit(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR) + b"\xc3",
        rodata=b"aaaa\x00bbbb\x00cccc\x00",
        symbols=(("func", TEXT_ADDR, 8),),
    )

    result = _analyze(path, {"basic.xref": {"max_strings": 1}})

    assert result.data["string_count"] == 1
    assert result.data["strings_truncated"] is True
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "XREF_STRINGS_TRUNCATED" in codes


@requires_capstone
def test_image_without_code_regions_warns_and_keeps_string_facts(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=b"",
        rodata=b"hello world\x00",
        symbols=(),
    )

    result = _analyze(path)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["code_region_count"] == 0
    assert result.data["string_count"] == 1
    assert result.data["xref_count"] == 0
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "XREF_NO_CODE_REGIONS" in codes


@requires_capstone
def test_missing_decoder_warns_and_keeps_string_facts(tmp_path, monkeypatch):
    import soinsight.infrastructure.disasm as disasm

    monkeypatch.setattr(disasm, "_MODULE", None)
    monkeypatch.setattr(disasm, "_SPEC", None)
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR) + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
    )

    result = _analyze(path)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["decoder"] is None
    assert result.data["string_count"] == 1
    assert result.data["xref_count"] == 0
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "XREF_DECODER_UNAVAILABLE" in codes


def test_format_text_reports_the_summary(tmp_path):
    path = _write_image(
        tmp_path / "sample.so",
        text=_lea_rip(RODATA_ADDR) + b"\xc3",
        rodata=b"hello world\x00",
        symbols=(("func", TEXT_ADDR, 8),),
    )

    result = _analyze(path)
    text = BasicXrefAnalyzer().format_text(result)

    assert "交叉引用" in text
    assert "hello world" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    path = tmp_path / "not-an-elf.bin"
    path.write_bytes(b"plain text")

    result = _analyze(path)

    assert BasicXrefAnalyzer().format_text(result) is None


def test_capability_is_declared_in_the_basic_module():
    from soinsight.modules import create_builtin_module_catalog

    catalog = create_builtin_module_catalog()
    capability = catalog.get("basic").get_capability("xref")

    assert capability.id == "basic.xref"
    assert "basic.xref" in catalog.get("basic").analyzer_ids
