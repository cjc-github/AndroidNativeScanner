"""Unit tests for the built-in advanced.constants analyzer."""

from pathlib import Path

from soinsight.analyzers.constants import AdvancedConstantsAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.constants import (
    SIGNATURES,
    ConstantSignature,
    families,
    scan,
)

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

# AES S-box head, its second word, and the reflected CRC32 polynomial.
AES_HEAD = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
AES_SECOND = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")
CRC32_WORD = bytes.fromhex("edb88320")
ZLIB_HEAD = bytes.fromhex("00010101010101010202020202020203")


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedConstantsAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.bin"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "constants"
    )
    assert AdvancedConstantsAnalyzer.metadata.id == capability.id == "advanced.constants"


def test_families_covers_the_signature_table():
    assert families() == ("cipher", "hash", "checksum", "compression", "encoding")


def test_scan_reports_a_signature_when_every_word_is_present():
    data = b"\x00" * 16 + AES_HEAD + AES_SECOND + b"\x11" * 8

    hits = scan(data)

    algorithms = {hit.algorithm for hit in hits}
    assert "AES" in algorithms
    aes = next(hit for hit in hits if hit.algorithm == "AES")
    assert aes.family == "cipher"
    assert 0x10 in aes.offsets


def test_scan_ignores_a_partial_signature():
    # Only the CRC32 word, no companion word: the signature must not fire.
    data = b"\x00" * 8 + CRC32_WORD

    hits = scan(data)

    # CRC32 is a single-word signature, so it does match; a multi-word
    # signature with one word present does not.
    assert {hit.algorithm for hit in hits} == {"CRC32"}


def test_scan_requires_all_words_of_a_multi_word_signature():
    data = b"\x00" * 8 + AES_HEAD + b"\xff" * 32
    single = ConstantSignature("Fake", "cipher", (AES_HEAD, CRC32_WORD))

    hits = scan(data, (single,))

    assert hits == ()


def test_scan_caps_occurrences_per_algorithm():
    repeated = (AES_HEAD + AES_SECOND + b"\x00" * 4) * 10

    hits = scan(repeated, max_hits_per_algorithm=3)

    aes = next(hit for hit in hits if hit.algorithm == "AES")
    assert len(aes.offsets) == 3


def test_scan_handles_empty_input():
    assert scan(b"") == ()
    assert scan(b"\x00" * 64) == ()


def test_scan_matches_zlib_and_base64_tables():
    assert any(hit.algorithm == "zlib deflate" for hit in scan(b"\x00" + ZLIB_HEAD))
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert any(hit.algorithm == "Base64" for hit in scan(b"\x00" + alphabet))


def test_analyzer_reports_hits_with_section_attribution(tmp_path):
    # A .rodata-shaped blob carrying the CRC32 table.
    blob = b"\x00" * 32 + CRC32_WORD + b"\x00" * 32
    sample = _write(
        tmp_path,
        build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=blob),
        name="libconstants.so",
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["signature_count"] == len(SIGNATURES)
    assert data["hit_count"] >= 1
    crc = next(hit for hit in data["hits"] if hit["algorithm"] == "CRC32")
    assert crc["family"] == "checksum"
    assert crc["offsets"] == [hex(32 + 0x40)]  # after the ELF header and .text
    assert crc["sections"] == [".text"]
    assert data["families"]["checksum"] == 1


def test_analyzer_reports_no_hits_for_plain_data(tmp_path):
    sample = _write(tmp_path, b"just some text, no constant tables here")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["hit_count"] == 0
    assert result.data["hits"] == []
    assert result.data["families"] == {}


def test_analyzer_works_on_a_non_elf_target(tmp_path):
    sample = _write(tmp_path, b"\x00" * 16 + CRC32_WORD, name="plain.bin")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    hit = result.data["hits"][0]
    assert hit["algorithm"] == "CRC32"
    # No ELF means no section attribution, not a failure.
    assert hit["sections"] == [None]


def test_analyzer_warns_when_the_input_is_truncated(tmp_path):
    sample = _write(tmp_path, b"\x00" * 64 + CRC32_WORD)

    result = _analyze(sample, capability_options={"advanced.constants": {"max_scan_bytes": 16}})

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["scan_truncated"] is True
    codes = {item.code for item in result.diagnostics}
    assert "CONSTANTS_INPUT_TRUNCATED" in codes
    # The tail was not scanned, so the constant table is not reported.
    assert result.data["hit_count"] == 0


def test_analyzer_clamps_invalid_option_values(tmp_path):
    sample = _write(tmp_path, b"\x00" * 16 + CRC32_WORD)

    result = _analyze(
        sample,
        capability_options={
            "advanced.constants": {"max_scan_bytes": "abc", "max_hits_per_algorithm": -1}
        },
    )

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["hit_count"] >= 1


def test_format_text_summarizes_hits(tmp_path):
    sample = _write(tmp_path, b"\x00" * 16 + CRC32_WORD)
    result = _analyze(sample)

    text = AdvancedConstantsAnalyzer().format_text(result)

    assert text.startswith("=== 特征常量 ===")
    assert "特征表: " in text
    assert "命中: " in text
    assert "CRC32" in text


def test_format_text_reports_an_empty_scan(tmp_path):
    sample = _write(tmp_path, b"nothing to see here")
    result = _analyze(sample)

    text = AdvancedConstantsAnalyzer().format_text(result)

    assert "未发现已知算法常量表" in text


def test_format_text_returns_none_for_failed_results(tmp_path):
    class _Result:
        status = AnalysisStatus.FAILED

    assert AdvancedConstantsAnalyzer().format_text(_Result()) is None
