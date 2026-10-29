"""Unit tests for the built-in advanced.obfuscation analyzer."""

from pathlib import Path

from soinsight.analyzers.obfuscation import AdvancedObfuscationAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.obfuscation import scan_sections


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedObfuscationAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "obfuscation"
    )
    assert capability.id == AdvancedObfuscationAnalyzer.metadata.id
    assert AdvancedObfuscationAnalyzer.metadata.id == "advanced.obfuscation"


def test_upx_banner_is_reported(tmp_path):
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    elf = build_elf64_with_symbols(
        SAMPLE_SYMBOLS,
        extra_sections={".text": b"UPX!\x00" + b"\x00" * 32},
    )
    result = _analyze(_write(tmp_path, elf, "sample.so"))

    signals = {item["signal"] for item in result.data["signals"]}
    assert "upx" in signals


def test_high_entropy_section_is_reported(tmp_path):
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols
    import os

    random_bytes = os.urandom(512)
    elf = build_elf64_with_symbols(
        SAMPLE_SYMBOLS,
        extra_sections={".data": random_bytes},
    )
    result = _analyze(_write(tmp_path, elf, "sample.so"))

    signals = {item["signal"] for item in result.data["signals"]}
    assert "high-entropy" in signals


def test_low_entropy_section_is_not_reported(tmp_path):
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    elf = build_elf64_with_symbols(
        SAMPLE_SYMBOLS,
        extra_sections={".data": b"\x00" * 512},
    )
    result = _analyze(_write(tmp_path, elf, "sample.so"))

    signals = {item["signal"] for item in result.data["signals"]}
    assert "high-entropy" not in signals


def test_non_elf_target_reports_no_signals(tmp_path):
    blob = b"just some bytes" + b"\x00" * 64
    result = _analyze(_write(tmp_path, blob, "blob.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["signal_count"] == 0


def test_input_larger_than_cap_warns(tmp_path):
    blob = b"\x00" * 70000
    result = _analyze(_write(tmp_path, blob, "big.bin"), capability_options={
        "advanced.obfuscation": {"max_scan_bytes": 100}
    })

    assert result.data["scan_truncated"] is True
    codes = [d.code for d in result.diagnostics]
    assert "OBFUSCATION_INPUT_TRUNCATED" in codes


def test_scan_sections_reports_the_ollvm_banner():
    hits = scan_sections(((".text", b"Obfuscator-LLVM" + b"\x00" * 32),), ("main",))

    by_name = {item.signal: item for item in hits}
    assert "ollvm" in by_name
    assert by_name["ollvm"].strength == "single"


def test_plain_llvm_runtime_symbols_are_not_ollvm():
    """SanitizerCoverage/PGO builds carry ``__llvm_profile_*``, not OLLVM."""
    hits = scan_sections(
        ((".text", b"\x00" * 32),),
        ("__llvm_profile_write_file", "__llvm_orderfile_write_file"),
    )

    assert "ollvm" not in {item.signal for item in hits}


def test_format_text_reports_the_summary(tmp_path):
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    elf = build_elf64_with_symbols(
        SAMPLE_SYMBOLS,
        extra_sections={".text": b"UPX!\x00" + b"\x00" * 32},
    )
    result = _analyze(_write(tmp_path, elf, "sample.so"))
    text = AdvancedObfuscationAnalyzer().format_text(result)

    assert "混淆识别" in text
    assert "upx" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze(_write(tmp_path, b"plain", "x.bin"))
    result.status = AnalysisStatus.FAILED

    assert AdvancedObfuscationAnalyzer().format_text(result) is None
