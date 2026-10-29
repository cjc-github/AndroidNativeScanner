"""Unit tests for the built-in advanced.algorithm analyzer."""

from pathlib import Path

from soinsight.analyzers.algorithm import AdvancedAlgorithmAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.algorithm import families, identify
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.constants import ConstantHit

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

AES_HEAD = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
AES_SECOND = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")
CRC32_WORD = bytes.fromhex("edb88320")


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedAlgorithmAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.bin"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "algorithm"
    )
    assert (
        AdvancedAlgorithmAnalyzer.metadata.id == capability.id == "advanced.algorithm"
    )


def test_families_covers_the_marker_tables():
    assert "cipher" in families()
    assert "hash" in families()
    assert "library" in families()
    assert "compression" in families()


def test_identify_reports_nothing_without_evidence():
    report = identify((), ("printf", "malloc"), ("hello world",))

    assert report.algorithms == ()
    assert report.corroborated_count == 0


def test_identify_reports_a_single_source_as_single_strength():
    report = identify((), ("AES_set_encrypt_key",), ())

    assert len(report.algorithms) == 1
    aes = report.algorithms[0]
    assert aes.algorithm == "AES"
    assert aes.family == "cipher"
    assert aes.strength == "single"
    assert aes.sources == ("symbols",)


def test_identify_corroborates_across_constants_symbols_and_strings():
    hits = (ConstantHit("AES", "cipher", (0x100,), ()),)

    report = identify(
        hits,
        ("AES_set_encrypt_key", "EVP_aes_128_cbc"),
        ("AES-128-CBC", "OpenSSL 1.1.1"),
    )

    by_name = {item.algorithm: item for item in report.algorithms}
    aes = by_name["AES"]
    assert aes.strength == "corroborated"
    assert aes.sources == ("constants", "strings", "symbols")
    assert any("AES_set_encrypt_key" in detail for detail in aes.evidence)
    assert any(detail.startswith("AES @ ") for detail in aes.evidence)
    # The library is a separate judgement from the primitive.
    assert by_name["OpenSSL"].family == "library"
    assert by_name["OpenSSL"].strength == "corroborated"
    assert report.corroborated_count == 2


def test_identify_separates_library_from_algorithm():
    report = identify(
        (),
        ("EVP_DigestUpdate",),
        ("libcrypto.so.1.1",),
    )

    by_name = {item.algorithm: item for item in report.algorithms}
    assert set(by_name) == {"OpenSSL"}
    assert by_name["OpenSSL"].family == "library"
    assert by_name["OpenSSL"].strength == "corroborated"


def test_identify_maps_every_constant_table_entry():
    from soinsight.infrastructure.constants import SIGNATURES

    for signature in SIGNATURES:
        report = identify((ConstantHit(signature.algorithm, signature.family, (0,), ()),), (), ())
        assert len(report.algorithms) >= 1, signature.algorithm


def test_analyzer_reports_algorithms_with_evidence(tmp_path):
    # An ELF whose .text carries the AES table and a symbol that names AES.
    blob = b"\x00" * 16 + AES_HEAD + AES_SECOND + b"\x00" * 16
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=blob),
        name="libcrypto.so",
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["constant_count"] >= 1
    assert data["symbol_count"] > 0
    assert data["algorithm_count"] >= 1
    for item in data["algorithms"]:
        assert item["algorithm"]
        assert item["family"]
        assert item["strength"] in ("single", "corroborated")
        assert item["sources"]
        assert item["evidence"]


def test_analyzer_reports_no_algorithms_for_plain_data(tmp_path):
    sample = _write(tmp_path, b"nothing cryptographic in here at all")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["algorithm_count"] == 0
    assert result.data["algorithms"] == []
    assert result.data["corroborated_count"] == 0


def test_analyzer_works_on_a_non_elf_target(tmp_path):
    sample = _write(
        tmp_path,
        b"\x00" * 8 + b"OpenSSL 1.1.1t   AES-256-CBC",
        name="notes.txt",
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["symbol_count"] == 0
    names = {item["algorithm"] for item in result.data["algorithms"]}
    assert "OpenSSL" in names
    assert "AES" in names


def test_analyzer_warns_when_the_input_is_truncated(tmp_path):
    sample = _write(tmp_path, b"\x00" * 64 + b"OpenSSL" + b"\x00" * 32)

    result = _analyze(
        sample,
        capability_options={"advanced.algorithm": {"max_scan_bytes": 16}},
    )

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["scan_truncated"] is True
    codes = {item.code for item in result.diagnostics}
    assert "ALGORITHM_INPUT_TRUNCATED" in codes
    # The tail was not scanned, so the OpenSSL string is not seen.
    assert result.data["algorithm_count"] == 0


def test_analyzer_clamps_invalid_option_values(tmp_path):
    sample = _write(tmp_path, b"OpenSSL AES-256-CBC")

    result = _analyze(
        sample,
        capability_options={
            "advanced.algorithm": {
                "max_scan_bytes": "abc",
                "max_symbols": -3,
                "max_strings": 0,
            }
        },
    )

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["algorithm_count"] >= 1


def test_format_text_summarizes_algorithms(tmp_path):
    sample = _write(tmp_path, b"OpenSSL 1.1.1  AES-128-CBC")
    result = _analyze(sample)

    text = AdvancedAlgorithmAnalyzer().format_text(result)

    assert text.startswith("=== 算法识别 ===")
    assert "证据: " in text
    assert "判定: " in text
    assert "AES" in text


def test_format_text_reports_no_algorithms(tmp_path):
    sample = _write(tmp_path, b"nothing to see here")
    result = _analyze(sample)

    text = AdvancedAlgorithmAnalyzer().format_text(result)

    assert "未识别出已知算法" in text


def test_format_text_returns_none_for_failed_results(tmp_path):
    class _Result:
        status = AnalysisStatus.FAILED

    assert AdvancedAlgorithmAnalyzer().format_text(_Result()) is None
