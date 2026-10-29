"""Unit tests for the built-in advanced.compiler analyzer."""

from pathlib import Path

from soinsight.analyzers.compiler import AdvancedCompilerAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.compiler import identify
from soinsight.infrastructure.config import RuntimeConfig


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedCompilerAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "compiler"
    )
    assert capability.id == AdvancedCompilerAnalyzer.metadata.id
    assert AdvancedCompilerAnalyzer.metadata.id == "advanced.compiler"


def test_identify_extracts_the_gcc_version_from_the_comment():
    hits = identify(
        "GCC: (GNU) 9.4.0\nsome other comment", "", ("_Unwind_Resume",)
    )

    by_name = {item.toolchain: item for item in hits}
    gcc = by_name["gcc"]
    assert gcc.version == "9.4.0"
    assert gcc.strength == "corroborated"
    sources = {ev.source for ev in gcc.evidence}
    assert "comment" in sources and "symbol" in sources


def test_identify_clang_from_the_comment_only():
    hits = identify("clang version 14.0.6", "", ("malloc",))

    by_name = {item.toolchain: item for item in hits}
    clang = by_name["clang"]
    assert clang.version == "14.0.6"
    assert clang.strength == "single"


def test_android_clang_banner_corroborates_the_ndk():
    hits = identify("Android clang version 14.0.6", "Android", ("malloc",))

    by_name = {item.toolchain: item for item in hits}
    assert by_name["clang"].strength == "corroborated"
    assert by_name["android-ndk"].strength == "corroborated"


def test_analyzer_reads_comment_and_android_note_from_an_elf(tmp_path):
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    elf = build_elf64_with_symbols(
        SAMPLE_SYMBOLS,
        extra_sections={
            ".comment": b"Android clang version 14.0.6\n",
            ".note.android.ident": b"Android\n",
        },
    )
    result = _analyze(_write(tmp_path, elf, "sample.so"))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["has_android_ident"] is True
    toolchains = {item["toolchain"] for item in result.data["toolchains"]}
    assert "clang" in toolchains
    assert "android-ndk" in toolchains
    assert result.data["comment_sections"] == (".comment",)


def test_non_elf_target_has_no_toolchain_from_sections(tmp_path):
    blob = b"just some bytes" + b"\x00" * 32
    result = _analyze(_write(tmp_path, blob, "blob.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["toolchain_count"] == 0
    assert result.data["has_build_id"] is False


def test_input_larger_than_cap_warns(tmp_path):
    blob = b"\x00" * 70000
    result = _analyze(_write(tmp_path, blob, "big.bin"), capability_options={
        "advanced.compiler": {"max_scan_bytes": 100}
    })

    assert result.data["scan_truncated"] is True
    codes = [d.code for d in result.diagnostics]
    assert "COMPILER_INPUT_TRUNCATED" in codes


def test_format_text_reports_the_summary(tmp_path):
    blob = b"GCC: (GNU) 9.4.0\n" + b"\x00" * 16
    result = _analyze(_write(tmp_path, blob, "sample.bin"))
    text = AdvancedCompilerAnalyzer().format_text(result)

    assert "编译器识别" in text
    assert "gcc" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze(_write(tmp_path, b"plain", "x.bin"))
    result.status = AnalysisStatus.FAILED

    assert AdvancedCompilerAnalyzer().format_text(result) is None
