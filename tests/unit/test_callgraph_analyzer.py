"""Unit tests for the built-in basic.callgraph analyzer.

The tests cover the three facts the capability promises: direct calls into
the image, PLT resolution into imported symbol names, and indirect call sites
recorded without a guessed callee.
"""

from pathlib import Path
import struct

import pytest

from soinsight.analyzers.callgraph import BasicCallgraphAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.callgraph import (
    build_call_graph,
    plt_imports,
    relocation_slots,
)
from soinsight.infrastructure.elf import parse_bytes

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

try:
    import capstone
except ModuleNotFoundError:  # pragma: no cover - exercised only off-host
    capstone = None

requires_capstone = pytest.mark.skipif(
    capstone is None, reason="capstone is not installed"
)

# x86-64: a caller, a callee and a PLT-style stub that dispatches through a
# GOT slot named by a rela.plt entry.
#
#   0x1000  caller: two direct calls plus one indirect call
#   0x1010  callee:  ret
#   0x1020  stub:    jmp through the GOT slot at 0x1030
X86_CODE = b"".join((
    b"\xe8\x0b\x00\x00\x00",                   # 0x1000 call 0x1010
    b"\xe8\x0b\x00\x00\x00",                   # 0x1005 call 0x1010
    b"\xff\xd0",                               # 0x100a call rax
    b"\xc3",                                   # 0x100c ret
    b"\x90\x90\x90",                           # 0x100d padding
    b"\xc3",                                   # 0x1010 ret, the callee
    b"\x90" * 0xE,                             # 0x1011 padding
    b"\xff\x25\x0a\x00\x00\x00",               # 0x1020 jmp qword ptr [rip+0xa]
    b"\x90" * 0xD,                             # 0x1026 padding
))

# AArch64: a caller with a direct bl and an indirect blr.
#
#   0x1000  bl 0x1010 ; blr x8 ; ret
#   0x1010  ret
AARCH64_CODE = (
    b"\x03\x00\x00\x94"                        # 0x1000 bl 0x1010
    + b"\x00\x01\x3f\xd6"                      # 0x1004 blr x8
    + b"\xc0\x03\x5f\xd6"                      # 0x1008 ret
    + b"\x1f\x20\x03\xd5"                      # 0x100c nop
    + b"\xc0\x03\x5f\xd6"                      # 0x1010 ret
    + b"\x1f\x20\x03\xd5" * 0x3B               # padding
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
    return BasicCallgraphAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="libsample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability(
        "callgraph"
    )
    assert BasicCallgraphAnalyzer.metadata.id == capability.id == "basic.callgraph"


@requires_capstone
def test_analyzer_resolves_local_and_indirect_calls(tmp_path):
    sample = _write(tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE))

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["machine"] == "x86-64"
    kinds = [edge["kind"] for edge in data["call_edges"]]
    assert "indirect" in kinds
    # Every edge carries a caller address; indirect edges carry no callee.
    for edge in data["call_edges"]:
        assert edge["caller"].startswith("0x")
        if edge["kind"] == "indirect":
            assert edge["callee"] is None
            assert edge["callee_name"] is None
        else:
            assert edge["callee"] is not None


@requires_capstone
def test_analyzer_resolves_aarch64_call_shapes(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, machine=183, text_bytes=AARCH64_CODE),
        name="libarm64.so",
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["machine"] == "AArch64"
    kinds = {edge["kind"] for edge in result.data["call_edges"]}
    # A direct bl plus an indirect blr; no PLT is present in this image.
    assert kinds <= {"local", "indirect"}


def test_relocation_slots_reads_rela_entries(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(
            SAMPLE_SYMBOLS,
            text_bytes=X86_CODE,
            # One JUMP_SLOT claiming the GOT slot the stub jumps through.
            rela_plt_bytes=struct.pack("<QQq", 0x1030, 1 << 32 | 7, 0),
        ),
    )
    data = sample.read_bytes()
    elf = parse_bytes(data)

    slots = relocation_slots(data, elf)

    assert slots == {0x1030: 1}


@requires_capstone
def test_plt_imports_maps_stub_to_relocated_symbol(tmp_path):
    # A single lazy stub at 0x1020: jmp qword ptr [rip + 0xa] reads the GOT
    # slot at 0x1030, which the .rela.plt entry claims for symbol 1
    # (Java_com_example_Foo_nativeInit in SAMPLE_SYMBOLS).
    stub = b"\xff\x25\x0a\x00\x00\x00" + b"\x90" * 0xA
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(
            SAMPLE_SYMBOLS,
            text_bytes=X86_CODE,
            plt_bytes=stub,
            plt_address=0x1020,
            rela_plt_bytes=struct.pack("<QQq", 0x1030, 1 << 32 | 7, 0),
        ),
    )
    data = sample.read_bytes()
    elf = parse_bytes(data)

    from soinsight.infrastructure import disasm

    imports = plt_imports(data, elf, disasm.decode_architecture)

    assert imports == {0x1020: "Java_com_example_Foo_nativeInit"}


def test_plt_imports_returns_empty_without_relocations(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE),
    )
    data = sample.read_bytes()
    elf = parse_bytes(data)

    from soinsight.infrastructure import disasm

    assert plt_imports(data, elf, disasm.decode_architecture) == {}


def test_build_call_graph_handles_an_empty_function_list():
    from soinsight.infrastructure.elf import parse_bytes

    elf = parse_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS))

    from soinsight.infrastructure import disasm

    graph = build_call_graph(b"", elf, [], disasm.decode_architecture)

    assert graph.edges == ()
    assert graph.callers_of == ()
    assert graph.edge_count == 0
    assert graph.indirect_count == 0


def test_build_call_graph_skips_zero_sized_functions():
    from soinsight.infrastructure import disasm
    from soinsight.infrastructure.elf import parse_bytes

    elf = parse_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE))
    data = build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE)

    graph = build_call_graph(data, elf, [("only", 0x1000, 0, "symbols")], disasm.decode_architecture)

    assert graph.edges == ()


def test_analyzer_warns_when_the_decoder_is_missing(tmp_path, monkeypatch):
    import soinsight.infrastructure.disasm as disasm

    monkeypatch.setattr(disasm, "_MODULE", None)
    monkeypatch.setattr(disasm, "_SPEC", None)
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    codes = {item.code for item in result.diagnostics}
    assert "CALLGRAPH_NO_DECODER" in codes
    assert result.data["edge_count"] == 0
    assert result.data["external_calls"] == []


def test_analyzer_warns_without_code_regions(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=b"")
    )

    result = _analyze(sample)

    codes = {item.code for item in result.diagnostics}
    assert "CALLGRAPH_NO_CODE_REGIONS" in codes
    assert result.data["edge_count"] == 0


def test_analyzer_rejects_non_elf(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_analyzer_truncates_at_the_edge_limit(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE),
    )

    result = _analyze(sample, capability_options={"basic.callgraph": {"max_edges": 1}})
    data = result.data

    assert data["truncated"] is True
    assert data["edge_count"] == 1
    codes = {item.code for item in result.diagnostics}
    assert "CALLGRAPH_TRUNCATED" in codes


def test_analyzer_clamps_invalid_option_values(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE),
    )

    result = _analyze(
        sample,
        capability_options={
            "basic.callgraph": {"max_functions": "abc", "max_edges": -5}
        },
    )

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["edge_count"] >= 0


@requires_capstone
def test_format_text_summarizes_call_facts(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_CODE),
    )
    result = _analyze(sample)

    text = BasicCallgraphAnalyzer().format_text(result)

    assert text.startswith("=== 调用图 ===")
    assert "架构: x86-64" in text
    assert "调用边: " in text
    assert "被调函数: " in text


def test_format_text_returns_none_for_failed_results(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")
    result = _analyze(sample)

    assert BasicCallgraphAnalyzer().format_text(result) is None
