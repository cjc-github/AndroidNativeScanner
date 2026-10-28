"""Unit tests for the built-in basic.disasm analyzer.

The tests cover the three facts the capability promises: instruction decoding,
function boundary recovery (symbol table first, prologue scan second) and code
region enumeration. Capstone is an optional dependency, so the degradation path
(no decoder) is exercised as well.
"""

from pathlib import Path

import pytest

from soinsight.analyzers.disasm import BasicDisasmAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.disasm import (
    capstone_version,
    decode_architecture,
    prologue_starts,
    symbol_functions,
)

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

# Capstone is an optional dependency: decoding tests are skipped when it is
# absent, while the boundary and degradation tests still run everywhere.
try:
    import capstone
except ModuleNotFoundError:  # pragma: no cover - exercised only off-host
    capstone = None

requires_capstone = pytest.mark.skipif(
    capstone is None, reason="capstone is not installed"
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
    return BasicDisasmAnalyzer().analyze(target, context)


# x86-64: push rbp; mov rbp,rsp; ret  and a second prologue at +0x20.
X86_TEXT = (
    b"\x55\x48\x89\xe5\xc3\xcc"
    + b"\x90" * 0x1A
    + b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\xc3"
    + b"\x90" * 0xE0
)

# AArch64: stp x29, x30, [sp, #-16]! ; ret  and a second prologue at +0x20.
AARCH64_TEXT = (
    b"\xfd\x7b\xbf\xa9\xc0\x03\x5f\xd6"
    + b"\x1f\x20\x03\xd5" * 6
    + b"\xfd\x7b\xbf\xa9\xc0\x03\x5f\xd6"
    + b"\x1f\x20\x03\xd5" * 0x38
)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability(
        "disasm"
    )
    assert BasicDisasmAnalyzer.metadata.id == capability.id == "basic.disasm"


def test_analyzer_declares_no_dependencies():
    # basic.disasm parses the ELF image itself; the capability chain
    # basic.file -> basic.elf -> basic.symbols is not a hard requirement.
    assert BasicDisasmAnalyzer.metadata.requires == ()


@requires_capstone
def test_analyzer_decodes_instructions_and_regions(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_TEXT)
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "basic.disasm"
    data = result.data
    assert data["machine"] == "x86-64"
    assert data["arch"] == "x86"
    assert data["decoder"] == capstone.__version__
    # The synthetic image only defines .text; real shared objects add .plt.
    assert data["code_region_count"] == 1
    assert data["code_regions"][0]["name"] == ".text"

    first = data["instructions"][0]
    assert first["address"] == "0x1000"
    assert first["mnemonic"] == "push"
    assert first["operands"] == "rbp"
    assert first["bytes"] == "55"
    assert data["instruction_count"] > 0
    assert data["truncated"] is False


def test_analyzer_prefers_symbol_bounds_over_prologue_scan(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_TEXT)
    )

    data = _analyze(sample).data
    symbol_bounds = [item for item in data["functions"] if item["source"] == "symbols"]

    # Every defined function symbol in the sample lands a boundary.
    assert data["symbol_function_count"] == 5
    assert len(symbol_bounds) == 5
    by_name = {item["name"]: item for item in data["functions"]}
    jni = by_name["Java_com_example_Foo_nativeInit"]
    assert jni["address"] == "0x1000"
    assert jni["size"] == 0x40
    assert jni["source"] == "symbols"
    # A symbol boundary never duplicates a prologue hit at the same address.
    assert by_name["_ZN3foo3barEi"]["address"] == "0x1080"


def test_analyzer_scans_prologues_for_symbol_less_gaps(tmp_path):
    # A stripped image: the prologue scan must fill the gaps between symbols.
    sample = tmp_path / "stripped.so"
    sample.write_bytes(
        build_elf64_with_symbols(
            SAMPLE_SYMBOLS, with_symtab=False, text_bytes=X86_TEXT
        )
    )

    data = _analyze(sample).data
    prologue = [item for item in data["functions"] if item["source"] == "prologue"]

    assert data["symbol_function_count"] == 5  # .dynsym still present
    # Every symbol boundary is a start, so the scan only reports symbol-less
    # addresses; a prologue hit never duplicates a symbol bound. Both the
    # endbr64 and the push-rbp inside the symbol-less gap are reported.
    assert [item["address"] for item in prologue] == ["0x1020", "0x1024"]
    assert all(item["name"].startswith("sub_") for item in prologue)


@requires_capstone
def test_analyzer_decodes_aarch64_samples(tmp_path):
    sample = tmp_path / "libarm64.so"
    sample.write_bytes(
        build_elf64_with_symbols(
            SAMPLE_SYMBOLS, machine=183, text_bytes=AARCH64_TEXT
        )
    )

    data = _analyze(sample).data

    assert data["machine"] == "AArch64"
    assert data["arch"] == "aarch64"
    assert data["instructions"][0]["mnemonic"] == "stp"
    prologue = [item for item in data["functions"] if item["source"] == "prologue"]
    assert [item["address"] for item in prologue] == ["0x1020"]


def test_analyzer_warns_on_unsupported_machine(tmp_path):
    sample = tmp_path / "libmips.so"
    sample.write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS, machine=8))

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    codes = {item.code for item in result.diagnostics}
    assert "DISASM_UNSUPPORTED_ARCH" in codes
    assert result.data["arch"] is None
    assert result.data["instructions"] == []
    assert result.data["instruction_count"] == 0
    # Boundaries from symbols remain usable without a decoder.
    assert result.data["symbol_function_count"] == 5


def test_analyzer_keeps_boundaries_when_the_decoder_is_missing(
    tmp_path, monkeypatch
):
    # Capstone is optional: a host without it must still receive boundary and
    # region facts, only the instruction stream is absent.
    import soinsight.infrastructure.disasm as disasm

    monkeypatch.setattr(disasm, "_MODULE", None)
    monkeypatch.setattr(disasm, "_SPEC", None)
    sample = tmp_path / "libsample.so"
    sample.write_bytes(
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_TEXT)
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    codes = {item.code for item in result.diagnostics}
    assert "DISASM_DECODER_UNAVAILABLE" in codes
    assert result.data["decoder"] is None
    assert result.data["instruction_count"] == 0
    assert result.data["instructions"] == []
    # Symbol bounds and code regions survive the missing decoder.
    assert result.data["symbol_function_count"] == 5
    assert result.data["function_count"] >= 5
    assert result.data["code_region_count"] == 1


def test_analyzer_reports_missing_code_regions(tmp_path):
    sample = tmp_path / "nocode.so"
    sample.write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=b""))

    result = _analyze(sample)

    codes = {item.code for item in result.diagnostics}
    assert "DISASM_NO_CODE_REGIONS" in codes
    assert result.data["code_region_count"] == 0
    # Symbol bounds survive without a code region: the addresses are still
    # known, but nothing can be decoded.
    assert result.data["function_count"] == 5
    assert result.data["instruction_count"] == 0


def test_analyzer_rejects_non_elf(tmp_path):
    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"not an elf file at all")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_analyzer_truncates_functions_and_instructions(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_TEXT)
    )

    result = _analyze(sample, capability_options={"basic.disasm": {"max_functions": 2}})
    data = result.data

    assert data["truncated"] is True
    assert data["function_count"] == 2
    codes = {item.code for item in result.diagnostics}
    assert "DISASM_TRUNCATED" in codes

    instruction_limited = _analyze(
        sample,
        capability_options={"basic.disasm": {"max_instructions": 3}},
    ).data
    assert instruction_limited["instruction_count"] == 3
    assert instruction_limited["truncated"] is True


def test_analyzer_clamps_invalid_option_values(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_TEXT)
    )

    result = _analyze(
        sample,
        capability_options={
            "basic.disasm": {"max_functions": "abc", "max_instructions": -5}
        },
    )

    # Invalid values fall back to the defaults; negative values clamp to 1.
    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["function_count"] > 1


def test_symbol_functions_deduplicates_across_tables():
    from soinsight.infrastructure.elf import parse_bytes

    image = build_elf64_with_symbols(SAMPLE_SYMBOLS)
    bounds = symbol_functions(parse_bytes(image))

    assert [name for name, *_ in bounds] == [
        "Java_com_example_Foo_nativeInit",
        "Java_com_example_Foo_nativeInit__ILjava_lang_String_2",
        "_ZN3foo3barEi",
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "_ZN7android7IBinderD2Ev",
    ]
    # The same address/size pair appears in both tables; the regular .symtab
    # entry wins so bounds carry one row per function.
    assert bounds[0] == ("Java_com_example_Foo_nativeInit", 0x1000, 0x40, ".symtab")


def test_prologue_starts_excludes_known_boundaries():
    starts = prologue_starts(X86_TEXT, 0x1000, "x86", 1, {0x1000})
    # 0x1020 holds the endbr64 prologue and 0x1024 its `push rbp`.
    assert starts == (0x1020, 0x1024)


@requires_capstone
def test_decode_architecture_maps_supported_machines():
    assert decode_architecture("x86-64") == (
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64,
    )
    assert decode_architecture("AArch64")[0] == capstone.CS_ARCH_ARM64
    assert decode_architecture("MIPS") is None


def test_capstone_version_matches_installed_module():
    if capstone is None:
        assert capstone_version() is None
    else:
        assert capstone_version() == capstone.__version__


def test_format_text_summarizes_facts(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=X86_TEXT)
    )
    result = _analyze(sample)

    text = BasicDisasmAnalyzer().format_text(result)

    assert text.startswith("=== 反汇编 ===")
    assert "架构: x86-64" in text
    assert "代码区域: 1 个" in text
    assert "函数边界: " in text
    assert "指令: " in text


def test_format_text_returns_none_for_failed_results(tmp_path):
    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"not an elf file at all")
    result = _analyze(sample)

    assert BasicDisasmAnalyzer().format_text(result) is None
