"""Unit tests for the built-in basic.dataflow analyzer.

The tests cover the two facts the capability promises: per-block use-def
chains and reaching definitions propagated across block boundaries. Register
liveness is derived from the operand text, so sub-register folding is
verified as well.
"""

from pathlib import Path

import pytest

from soinsight.analyzers.dataflow import BasicDataflowAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.cfg import build_cfg
from soinsight.infrastructure.dataflow import analyse, instruction_locations

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

try:
    import capstone
except ModuleNotFoundError:  # pragma: no cover - exercised only off-host
    capstone = None

requires_capstone = pytest.mark.skipif(
    capstone is None, reason="capstone is not installed"
)

# x86-64: a value defined in the entry block is used in a later block.
#
#   0x1000  mov eax, 0
#   0x1005  jmp 0x100c
#   0x1007  mov eax, 1
#   0x100c  add eax, ebx   (eax reaches from 0x1000 and 0x1007)
#   0x100e  ret
X86_FLOW = (
    b"\xb8\x00\x00\x00\x00"                    # 0x1000 mov eax, 0
    + b"\xeb\x03"                              # 0x1005 jmp 0x100c
    + b"\xb8\x01\x00\x00\x00"                  # 0x1007 mov eax, 1
    + b"\x01\xd8"                              # 0x100c add eax, ebx
    + b"\xc3"                                  # 0x100e ret
    + b"\x90" * 0xF0
)

# AArch64: w0 is defined in the entry block and used after a branch.
#
#   0x1000  mov w0, #0
#   0x1004  b 0x100c
#   0x1008  mov w0, #1
#   0x100c  add w0, w0, #2
#   0x1010  ret
AARCH64_FLOW = (
    b"\x00\x00\x80\x52"                        # 0x1000 mov w0, #0
    + b"\x01\x00\x00\x14"                      # 0x1004 b 0x100c
    + b"\x20\x00\x80\x52"                      # 0x1008 mov w0, #1
    + b"\x00\x04\x00\x0b"                      # 0x100c add w0, w0, #2
    + b"\xc0\x03\x5f\xd6"                      # 0x1010 ret
    + b"\x1f\x20\x03\xd5" * 0x3C
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
    return BasicDataflowAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="libsample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability(
        "dataflow"
    )
    assert BasicDataflowAnalyzer.metadata.id == capability.id == "basic.dataflow"


def test_normalise_register_folds_sub_registers():
    assert instruction_locations("mov", "rbp, rsp", "x86") == ({"rsp"}, {"rbp"})
    # eax/ax/al are the same location as rax.
    assert instruction_locations("mov", "eax, 1", "x86") == (set(), {"rax"})
    assert instruction_locations("add", "rax, rbx", "x86") == ({"rbx"}, {"rax"})
    # A memory operand contributes its base register, not an address.
    assert instruction_locations(
        "mov", "eax, dword ptr [rbp - 4]", "x86"
    ) == ({"rbp"}, {"rax"})
    # AArch64 w<n> folds into x<n>; the destination is the first operand, so
    # ``add w0, w0, #2`` only writes x0.
    assert instruction_locations("add", "w0, w0, #2", "aarch64") == (
        set(),
        {"x0"},
    )
    assert instruction_locations("add", "w1, w0, #2", "aarch64") == (
        {"x0"},
        {"x1"},
    )
    assert instruction_locations("ldr", "x0, [x1, #8]", "aarch64") == (
        {"x1"},
        {"x0"},
    )


def test_instruction_locations_treats_comparisons_as_reads_only():
    assert instruction_locations("cmp", "eax, 3", "x86") == ({"rax"}, set())
    assert instruction_locations("test", "rax, rax", "x86") == ({"rax"}, set())
    assert instruction_locations("cbz", "w0, 0x1000", "aarch64") == ({"x0"}, set())


def test_analyse_propagates_definitions_across_blocks():
    instructions = [
        (0x1000, 5, "mov", "eax, 0"),
        (0x1005, 2, "jmp", "0x100c"),
        (0x1007, 5, "mov", "eax, 1"),
        (0x100c, 2, "add", "eax, ebx"),
        (0x100e, 1, "ret", ""),
    ]
    graph = build_cfg(instructions)

    flow = analyse(instructions, graph, "x86")

    assert flow.def_count == 3  # two eax defs plus the add's eax def
    assert flow.use_count == 1  # ebx is the only read
    # The use of rbx has no reaching definition anywhere in this function.
    block = flow.blocks[-1]
    assert block.uses[0].location == "rbx"
    assert block.uses[0].reaching == ()


def test_analyse_reports_use_of_a_value_defined_earlier_in_the_block():
    instructions = [
        (0x1000, 5, "mov", "eax, 0"),
        (0x1005, 2, "add", "eax, ebx"),
        (0x1007, 1, "ret", ""),
    ]
    graph = build_cfg(instructions)

    flow = analyse(instructions, graph, "x86")
    block = flow.blocks[0]

    uses = {use.location: use for use in block.uses}
    # eax is the destination of the add, so the only use is rbx; eax's own
    # definition is reported separately in the block's defs.
    assert set(uses) == {"rbx"}
    assert block.defs[0].location == "rax"
    assert block.defs[0].address == 0x1000


def test_analyse_handles_an_empty_stream():
    flow = analyse([], build_cfg([]), "x86")

    assert flow.blocks == ()
    assert flow.def_count == 0
    assert flow.use_count == 0
    assert flow.reaching_pairs == 0


def test_analyse_respects_the_pair_limit():
    instructions = [
        (0x1000, 5, "mov", "eax, 0"),
        (0x1005, 2, "jmp", "0x100c"),
        (0x1007, 5, "mov", "eax, 1"),
        (0x100c, 2, "add", "eax, ebx"),
        (0x100e, 1, "ret", ""),
    ]
    graph = build_cfg(instructions)

    flow = analyse(instructions, graph, "x86", max_pairs=0)

    # The limit suppresses reaching pairs but keeps the use/def facts.
    assert flow.reaching_pairs == 0
    assert flow.use_count == 1


@requires_capstone
def test_analyzer_reports_block_level_use_def(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_FLOW)
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["machine"] == "x86-64"
    assert data["scope"] == "intra-procedural"
    assert data["function_count"] > 0
    assert data["def_count"] > 0
    assert data["use_count"] > 0
    assert data["block_count"] > 0
    for function in data["functions"]:
        assert function["block_count"] >= 1
        for block in function["blocks"]:
            assert block["start"].startswith("0x")
            for definition in block["defs"]:
                assert definition["location"]
                assert definition["address"].startswith("0x")
            for use in block["uses"]:
                assert use["location"]
                for definition in use["reaching"]:
                    assert definition["address"].startswith("0x")


@requires_capstone
def test_analyzer_handles_aarch64_registers(tmp_path):
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, machine=183, text_bytes=AARCH64_FLOW),
        name="libarm64.so",
    )

    data = _analyze(sample).data

    assert data["machine"] == "AArch64"
    assert data["def_count"] > 0
    locations = {
        definition["location"]
        for function in data["functions"]
        for block in function["blocks"]
        for definition in block["defs"]
    }
    assert locations <= {"x0", "x1", "x2", "sp", "v0"}


def test_analyzer_warns_when_the_decoder_is_missing(tmp_path, monkeypatch):
    import soinsight.infrastructure.disasm as disasm

    monkeypatch.setattr(disasm, "_MODULE", None)
    monkeypatch.setattr(disasm, "_SPEC", None)
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_FLOW)
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    codes = {item.code for item in result.diagnostics}
    assert "DATAFLOW_NO_DECODER" in codes
    assert result.data["def_count"] == 0
    assert result.data["use_count"] == 0


def test_analyzer_warns_without_code_regions(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=b"")
    )

    result = _analyze(sample)

    codes = {item.code for item in result.diagnostics}
    assert "DATAFLOW_NO_CODE_REGIONS" in codes
    assert result.data["function_count"] == 0


def test_analyzer_rejects_non_elf(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_analyzer_truncates_the_function_list(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_FLOW)
    )

    result = _analyze(sample, capability_options={"basic.dataflow": {"max_functions": 1}})
    data = result.data

    assert data["truncated"] is True
    assert data["function_count"] == 1
    codes = {item.code for item in result.diagnostics}
    assert "DATAFLOW_TRUNCATED" in codes


def test_analyzer_clamps_invalid_option_values(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_FLOW)
    )

    result = _analyze(
        sample,
        capability_options={
            "basic.dataflow": {"max_functions": "abc", "max_pairs": -5}
        },
    )

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["function_count"] >= 1


@requires_capstone
def test_format_text_summarizes_data_flow(tmp_path):
    sample = _write(
        tmp_path, build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_FLOW)
    )
    result = _analyze(sample)

    text = BasicDataflowAnalyzer().format_text(result)

    assert text.startswith("=== 数据流 ===")
    assert "架构: x86-64" in text
    assert "范围: " in text
    assert "定义: " in text
    assert "使用: " in text
    assert "到达定义对: " in text


def test_format_text_returns_none_for_failed_results(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")
    result = _analyze(sample)

    assert BasicDataflowAnalyzer().format_text(result) is None
