"""Unit tests for the built-in advanced.library analyzer."""

from pathlib import Path

from soinsight.analyzers.library import AdvancedLibraryAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.library import identify


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedLibraryAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "library"
    )
    assert capability.id == AdvancedLibraryAnalyzer.metadata.id
    assert AdvancedLibraryAnalyzer.metadata.id == "advanced.library"


def test_identify_matches_needed_symbols_and_versions():
    report = identify(
        needed=("libc.so", "libm.so", "libcrypto.so"),
        soname=None,
        symbol_names=("EVP_aes_256_gcm", "SSL_CTX_new", "malloc"),
        string_values=("OpenSSL 1.1.1k", "some text"),
    )

    by_name = {item.library: item for item in report.libraries}
    assert "OpenSSL" in by_name
    openssl = by_name["OpenSSL"]
    assert openssl.strength == "corroborated"
    sources = {ev.source for ev in openssl.evidence}
    assert {"needed", "symbol", "string"} <= sources
    assert "zlib" not in by_name


def test_identify_prefix_matches_mangled_cpp_symbols():
    report = identify(
        needed=(),
        soname=None,
        symbol_names=("_ZSt12__ostream_insert", "_ZN6google8protobuf7MessageC1Ev"),
        string_values=(),
    )

    by_name = {item.library: item for item in report.libraries}
    assert "libc++" in by_name or "libstdc++" in by_name
    assert "protobuf" in by_name


def test_identify_single_evidence_is_weak():
    report = identify(
        needed=(),
        soname=None,
        symbol_names=("inflate",),
        string_values=("no version string here",),
    )

    zlib = next(item for item in report.libraries if item.library == "zlib")
    assert zlib.strength == "single"


def test_analyzer_reports_libraries_from_an_elf(tmp_path):
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    symbols = SAMPLE_SYMBOLS + [
        ("inflate", 1, 2, 1, 0x2000, 0x20),
        ("EVP_aes_256_gcm", 1, 2, 1, 0x2010, 0x10),
    ]
    elf = build_elf64_with_symbols(symbols)
    result = _analyze(_write(tmp_path, elf, "sample.so"))

    assert result.status == AnalysisStatus.SUCCESS
    libraries = {item["library"] for item in result.data["libraries"]}
    assert "zlib" in libraries
    assert "OpenSSL" in libraries


def test_non_elf_target_uses_strings_only(tmp_path):
    blob = b"padding OpenSSL 1.1.1k more bytes zlib 1.2.11 tail"
    result = _analyze(_write(tmp_path, blob, "blob.bin"))

    libraries = {item["library"] for item in result.data["libraries"]}
    assert "OpenSSL" in libraries
    assert "zlib" in libraries


def test_unknown_binary_reports_no_libraries(tmp_path):
    blob = b"\x00" * 64 + b"nothing recognizable here" + b"\x00" * 16
    result = _analyze(_write(tmp_path, blob, "plain.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["library_count"] == 0


def test_input_larger_than_cap_warns(tmp_path):
    blob = b"\x00" * 70000
    result = _analyze(_write(tmp_path, blob, "big.bin"), capability_options={
        "advanced.library": {"max_scan_bytes": 100}
    })

    assert result.data["scan_truncated"] is True
    codes = [d.code for d in result.diagnostics]
    assert "LIBRARY_INPUT_TRUNCATED" in codes


def test_format_text_reports_the_summary(tmp_path):
    blob = b"OpenSSL 1.1.1k zlib 1.2.11"
    result = _analyze(_write(tmp_path, blob, "blob.bin"))
    text = AdvancedLibraryAnalyzer().format_text(result)

    assert "第三方库识别" in text
    assert "OpenSSL" in text
    assert "zlib" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze(_write(tmp_path, b"plain", "x.bin"))
    result.status = AnalysisStatus.FAILED

    assert AdvancedLibraryAnalyzer().format_text(result) is None
