"""Unit tests for the built-in basic.cfg analyzer and CFG construction."""

from pathlib import Path

import pytest

from soinsight.analyzers.cfg import BasicCfgAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.cfg import (
    build_cfg,
    classify_edge,
    direct_target,
    is_terminator,
)

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

try:
    import capstone
except ModuleNotFoundError:  # pragma: no cover - exercised only off-host
    capstone = None

requires_capstone = pytest.mark.skipif(
    capstone is None, reason="capstone is not installed"
)

# x86-64: a loop body. Entry compares, a conditional jump backwards closes
# the loop, and the exit path falls through to a return.
LOOP_TEXT = (
    b"\x55\x48\x89\xe5"                    # 0x1000 push rbp; mov rbp,rsp
    b"\xc7\x45\xfc\x00\x00\x00\x00"        # 0x1004 mov [rbp-4], 0
    b"\x8b\x45\xfc"                        # 0x100b mov eax, [rbp-4]
    b"\x3b\x45\xf8"                        # 0x100e cmp eax, [rbp-8]
    b"\x7d\x08"                            # 0x1011 jge 0x101b
    b"\x83\x45\xfc\x01"                    # 0x1013 add [rbp-4], 1
    b"\xeb\xf2"                            # 0x1017 jmp 0x100b
    b"\x90"                                # 0x1019 nop
    b"\x5d\xc3"                            # 0x101a pop rbp; ret
    + b"\x90" * 0xE0
)

# AArch64: cbz jumps backwards to the loop head.
AARCH64_LOOP_TEXT = (
    b"\xfd\x7b\xbf\xa9"                    # 0x1000 stp x29,x30,[sp,#-16]!
    b"\x00\x00\x80\x52"                    # 0x1004 mov w0, #0
    b"\x40\x00\x80\x52"                    # 0x1008 mov w0, #2
    b"\xe0\x03\x00\xb9"                    # 0x100c str w0, [sp]
    b"\xe0\x07\x40\xb9"                    # 0x1010 ldr w0, [sp]
    b"\x00\x00\x00\x34"                    # 0x1014 cbz w0, 0x1014
    b"\x01\x00\x00\x14"                    # 0x1018 b 0x1010
    b"\xc0\x03\x5f\xd6"                    # 0x101c ret
    + b"\x1f\x20\x03\xd5" * 0x39
)


def _target(path: Path) -> AnalysisTarget:
    data = path.read_bytes()
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=len(data),
        sha256="test-sha256",
    )


def _analyze(path: Path, **extra) -> object:
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return BasicCfgAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="libsample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability("cfg")
    assert BasicCfgAnalyzer.metadata.id == capability.id == "basic.cfg"


def test_is_terminator_recognises_control_flow():
    assert is_terminator("jmp")
    assert is_terminator("je")
    assert is_terminator("call")
    assert is_terminator("ret")
    assert is_terminator("b.eq")
    assert is_terminator("cbz")
    assert not is_terminator("mov")
    assert not is_terminator("cmp")


def test_direct_target_parses_literals_only():
    assert direct_target("0x101b") == 0x101B
    assert direct_target("4139") == 4139
    assert direct_target("#0x1010") == 0x1010
    assert direct_target("rax") is None
    assert direct_target("qword ptr [rip + 0x10]") is None
    assert direct_target("") is None


def test_classify_edge_separates_direct_from_indirect():
    assert classify_edge("jmp", "0x1000") == "branch"
    assert classify_edge("jmp", "rax") == "jump_indirect"
    assert classify_edge("je", "0x1000") == "cond"
    assert classify_edge("call", "0x1000") == "call"
    assert classify_edge("call", "rax") == "call_indirect"
    assert classify_edge("ret", "") == "return"
    assert classify_edge("cbz", "w0, 0x1010") == "cond"


def test_build_cfg_splits_blocks_and_edges():
    instructions = [
        (0x1000, 4, "mov", "eax, 1"),
        (0x1004, 2, "cmp", "eax, 2"),
        (0x1006, 2, "je", "0x100c"),      # terminator of the entry block
        (0x1008, 1, "nop", ""),
        (0x1009, 1, "nop", ""),
        (0x100a, 1, "nop", ""),
        (0x100b, 1, "ret", ""),
        (0x100c, 1, "ret", ""),
    ]

    graph = build_cfg(instructions)

    assert graph.entry == 0x1000
    # Only jump targets and post-terminator addresses start a block, so the
    # mov/cmp/je prologue shares the entry block.
    assert [hex(block.start) for block in graph.blocks] == [
        "0x1000",
        "0x1008",
        "0x100c",
    ]
    by_start = {block.start: block for block in graph.blocks}
    entry = by_start[0x1000]
    assert entry.terminator == "je"
    assert entry.end == 0x1008
    assert entry.successors == (0x1008, 0x100C)
    taken = by_start[0x1008]
    assert taken.terminator == "ret"
    assert taken.successors == ()
    assert graph.edges == (
        (0x1000, 0x1008, "cond"),
        (0x1000, 0x100C, "cond"),
    )
    assert graph.loops == ()


def test_build_cfg_detects_a_back_edge_loop():
    instructions = [
        (0x1000, 4, "mov", "eax, 0"),
        (0x1004, 2, "cmp", "eax, 3"),
        (0x1006, 2, "jge", "0x100e"),   # 0x1000 block: exit to 0x100e
        (0x1008, 1, "inc", "eax"),
        (0x1009, 2, "jmp", "0x1004"),   # 0x1008 block: back edge
        (0x100b, 1, "ret", ""),
        (0x100e, 1, "ret", ""),
    ]

    graph = build_cfg(instructions)

    # 0x1004 is the backward jump target, so it becomes a leader even though
    # the compare itself sits at the start of the entry block's second half.
    # The jump therefore targets a block start, which closes a cycle.
    assert [block.start for block in graph.blocks] == [
        0x1000,
        0x1004,
        0x1008,
        0x100B,
        0x100E,
    ]
    kinds = {(source, target): kind for source, target, kind in graph.edges}
    assert kinds[(0x1000, 0x1004)] == "fallthrough"
    assert kinds[(0x1004, 0x1008)] == "cond"
    assert kinds[(0x1004, 0x100E)] == "cond"
    assert kinds[(0x1008, 0x1004)] == "branch"
    # The backward jump targets the compare block, closing the loop.
    assert graph.loops == ((0x1004, 0x1008),)


def test_build_cfg_detects_a_loop_over_block_starts():
    instructions = [
        (0x1000, 4, "mov", "eax, 0"),
        (0x1004, 2, "jmp", "0x1008"),   # 0x1000 block ends here
        (0x1006, 1, "ret", ""),
        (0x1008, 2, "cmp", "eax, 3"),
        (0x100a, 2, "jge", "0x1010"),
        (0x100c, 1, "inc", "eax"),
        (0x100d, 2, "jmp", "0x1008"),   # 0x100c block: back edge to 0x1008
        (0x1010, 1, "ret", ""),
    ]

    graph = build_cfg(instructions)

    assert [block.start for block in graph.blocks] == [
        0x1000,
        0x1006,
        0x1008,
        0x100C,
        0x1010,
    ]
    kinds = {(source, target): kind for source, target, kind in graph.edges}
    assert kinds[(0x1000, 0x1008)] == "branch"
    assert kinds[(0x1008, 0x100C)] == "cond"
    assert kinds[(0x1008, 0x1010)] == "cond"
    assert kinds[(0x100C, 0x1008)] == "branch"
    # The backward jump closes a cycle over the compare and increment blocks.
    assert graph.loops == ((0x1008, 0x100C),)


def test_build_cfg_marks_indirect_edges_without_guessing():
    instructions = [
        (0x1000, 2, "call", "rax"),
        (0x1002, 2, "jmp", "qword ptr [rax]"),
        (0x1004, 1, "ret", ""),
    ]

    graph = build_cfg(instructions)

    # The call still returns to the fall-through block, but the indirect jump
    # leaves no successor because the target is unknown.
    by_start = {block.start: block for block in graph.blocks}
    assert by_start[0x1000].terminator == "call"
    assert by_start[0x1000].successors == (0x1002,)
    assert by_start[0x1002].successors == ()
    assert graph.edges == ((0x1000, 0x1002, "call_indirect"),)
    assert graph.loops == ()


def test_build_cfg_handles_empty_and_single_instruction_streams():
    empty = build_cfg([])
    assert empty.entry is None
    assert empty.blocks == ()

    single = build_cfg([(0x1000, 1, "ret", "")])
    assert single.entry == 0x1000
    assert single.block_count == 1
    assert single.blocks[0].terminator == "ret"
    assert single.blocks[0].successors == ()


def test_build_cfg_sorts_unordered_instructions():
    instructions = [
        (0x1004, 1, "ret", ""),
        (0x1000, 4, "mov", "eax, 1"),
    ]

    graph = build_cfg(instructions)

    assert graph.entry == 0x1000
    # The mov is not a terminator, so the whole stream is one block ending in
    # the ret: nothing splits it and no edge is provable.
    assert [block.start for block in graph.blocks] == [0x1000]
    assert graph.blocks[0].end == 0x1005
    assert graph.blocks[0].terminator == "ret"
    assert graph.edges == ()


@requires_capstone
def test_analyzer_builds_cfg_for_every_function(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=LOOP_TEXT),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["machine"] == "x86-64"
    assert data["function_count"] > 0
    assert data["block_count"] > 0
    assert data["edge_count"] > 0
    # The loop in .text is reachable from the first function, which starts at
    # 0x1000 and therefore owns the backward jump.
    first = data["functions"][0]
    assert first["address"] == "0x1000"
    assert first["block_count"] >= 3
    assert first["loop_count"] >= 1


@requires_capstone
def test_analyzer_reports_loop_blocks_edges_and_kinds(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=LOOP_TEXT),
    )

    data = _analyze(sample).data
    function = data["functions"][0]

    kinds = {edge["kind"] for edge in function["edges"]}
    assert "cond" in kinds
    assert "branch" in kinds
    # The backward jump closes the loop.
    assert any(
        edge["kind"] == "branch"
        and _int(edge["target"]) < _int(edge["source"])
        for edge in function["edges"]
    )
    assert len(function["loops"]) >= 1
    for block in function["blocks"]:
        assert _int(block["end"]) > _int(block["start"])


@requires_capstone
def test_analyzer_handles_aarch64_conditional_branches(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(
            SAMPLE_SYMBOLS, machine=183, text_bytes=AARCH64_LOOP_TEXT
        ),
        name="libarm64.so",
    )

    data = _analyze(sample).data

    assert data["machine"] == "AArch64"
    function = data["functions"][0]
    assert function["block_count"] >= 3
    # The backward `b` closes the loop over the load and cbz blocks.
    assert function["loop_count"] >= 1


def test_analyzer_warns_when_the_decoder_is_missing(tmp_path, monkeypatch):
    import soinsight.infrastructure.disasm as disasm

    monkeypatch.setattr(disasm, "_MODULE", None)
    monkeypatch.setattr(disasm, "_SPEC", None)
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=LOOP_TEXT),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    codes = {item.code for item in result.diagnostics}
    assert "CFG_NO_DECODER" in codes
    assert result.data["function_count"] == 0
    assert result.data["block_count"] == 0


def test_analyzer_warns_without_code_regions(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=b"")
    )

    result = _analyze(sample)

    codes = {item.code for item in result.diagnostics}
    assert "CFG_NO_CODE_REGIONS" in codes
    assert result.data["block_count"] == 0


def test_analyzer_rejects_non_elf(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_analyzer_truncates_the_function_list(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=LOOP_TEXT),
    )

    result = _analyze(sample, capability_options={"basic.cfg": {"max_functions": 1}})
    data = result.data

    assert data["truncated"] is True
    assert data["function_count"] == 1
    codes = {item.code for item in result.diagnostics}
    assert "CFG_TRUNCATED" in codes


def test_analyzer_clamps_invalid_option_values(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=LOOP_TEXT),
    )

    result = _analyze(
        sample,
        capability_options={
            "basic.cfg": {"max_functions": "abc", "max_instructions": -5}
        },
    )

    # Invalid values fall back to the defaults; negative values clamp to 1,
    # which leaves at least one function analysed.
    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["function_count"] >= 1


@requires_capstone
def test_format_text_summarizes_control_flow(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=LOOP_TEXT),
    )
    result = _analyze(sample)

    text = BasicCfgAnalyzer().format_text(result)

    assert text.startswith("=== 控制流图 ===")
    assert "架构: x86-64" in text
    assert "基本块: " in text
    assert "边: " in text
    assert "回边环: " in text


def test_format_text_returns_none_for_failed_results(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")
    result = _analyze(sample)

    assert BasicCfgAnalyzer().format_text(result) is None


def _int(value) -> int:
    return int(value, 16)
