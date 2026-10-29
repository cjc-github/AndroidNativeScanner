"""Unit tests for the built-in advanced.file-format analyzer."""

import struct
from pathlib import Path

import pytest

from soinsight.analyzers.file_format import AdvancedFileFormatAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.formats import FormatHit, scan


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedFileFormatAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.bin"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "file-format"
    )
    assert capability.id == AdvancedFileFormatAnalyzer.metadata.id
    assert AdvancedFileFormatAnalyzer.metadata.id == "advanced.file-format"


def test_outer_zip_and_embedded_png_are_reported(tmp_path):
    zip_head = b"PK\x03\x04" + b"\x14\x00"
    png = b"\x89PNG\r\n\x1a\n" + b"IHDR" + b"\x00\x00\x00\x01" + b"\x00" * 40
    blob = zip_head + b"\x00" * 60 + png + b"PK\x05\x06" + b"\x00" * 22

    result = _analyze(_write(tmp_path, blob, "bundle.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["outer_format"] == "zip"
    assert result.data["format_count"] == 2
    by_format = {entry["format"]: entry for entry in result.data["formats"]}
    assert by_format["zip"]["verified"] is True
    assert by_format["png"]["verified"] is True
    # 6-byte zip header + 60 bytes of padding.
    assert by_format["png"]["offset"] == hex(6 + 60)


def test_jpeg_needs_both_markers_to_verify(tmp_path):
    head_only = b"\xff\xd8\xff\xe0" + b"\x00" * 100
    full = b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"\xff\xd9"

    head_result = _analyze(_write(tmp_path, head_only, "a.jpg"))
    full_result = _analyze(_write(tmp_path, full, "b.jpg"))

    head_entry = head_result.data["formats"][0]
    full_entry = full_result.data["formats"][0]
    assert head_entry["verified"] is False
    assert full_entry["verified"] is True


def test_dex_needs_version_digits(tmp_path):
    good = b"\x00" * 8 + b"dex\n039\x00" + b"\x00" * 20
    bad = b"dex\n!!!" + b"\x00" * 20

    good_result = _analyze(_write(tmp_path, good, "classes.dex"))
    bad_result = _analyze(_write(tmp_path, bad, "not.dex"))

    good_dex = next(e for e in good_result.data["formats"] if e["format"] == "dex")
    bad_dex = next(e for e in bad_result.data["formats"] if e["format"] == "dex")
    assert good_dex["verified"] is True
    assert bad_dex["verified"] is False


def test_elf_hits_are_attributed_to_a_section(tmp_path):
    from tests.unit.elf_builder import SHT_PROGBITS, build_elf

    # A second, embedded ELF image inside .text; the outer header at offset 0
    # is not part of any section, the embedded one is.
    embedded = b"\x7fELF" + b"\x02\x01\x01"
    text = b"\x90" * 0x20 + embedded + b"\x90" * 8
    sections = [
        {
            "name": ".text",
            "type": SHT_PROGBITS,
            "flags": 0x6,
            "addr": 0x1000,
            "data": text,
        },
    ]
    elf = build_elf(sections)
    result = _analyze(_write(tmp_path, elf, "sample.so"))

    formats = result.data["formats"]
    assert result.data["outer_format"] == "elf"
    outer = [e for e in formats if e["offset"] == "0x0" and e["format"] == "elf"]
    assert outer and outer[0]["section"] is None
    embedded_hits = [e for e in formats if e["format"] == "elf" and e["offset"] != "0x0"]
    assert embedded_hits and embedded_hits[0]["section"] == ".text"


def test_non_elf_target_works_and_has_no_section(tmp_path):
    blob = b"junk" + b"\x00" * 4 + b"SQLite format 3\x00" + b"\x00" * 10

    result = _analyze(_write(tmp_path, blob, "blob.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    sqlite = [e for e in result.data["formats"] if e["format"] == "sqlite"]
    assert sqlite and sqlite[0]["section"] is None


def test_input_larger_than_cap_warns_and_truncates(tmp_path):
    blob = b"PK\x03\x04" + b"\x00" * 70000
    result = _analyze(_write(tmp_path, blob, "big.bin"), capability_options={
        "advanced.file-format": {"max_scan_bytes": 100}
    })

    assert result.data["scan_truncated"] is True
    codes = [d.code for d in result.diagnostics]
    assert "FORMAT_INPUT_TRUNCATED" in codes


def test_max_hits_limits_the_report(tmp_path):
    blob = b"%PDF-" * 50
    result = _analyze(_write(tmp_path, blob, "many.bin"), capability_options={
        "advanced.file-format": {"max_hits": 5}
    })

    assert result.data["format_count"] <= 5


def test_format_text_reports_the_summary(tmp_path):
    blob = b"PK\x03\x04" + b"\x00" * 40 + b"PK\x05\x06" + b"\x00" * 22
    result = _analyze(_write(tmp_path, blob, "outer.bin"))
    text = AdvancedFileFormatAnalyzer().format_text(result)

    assert "文件格式识别" in text
    assert "zip" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze(_write(tmp_path, b"plain text", "x.bin"))
    result.status = AnalysisStatus.FAILED

    assert AdvancedFileFormatAnalyzer().format_text(result) is None


def test_scan_reports_both_cafebabe_interpretations():
    blob = b"\x00" * 4 + b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x02" + b"\x00" * 20
    hits = {hit.format: hit for hit in scan(blob)}

    assert "fat-macho" in hits
    assert "java-class" in hits
    assert hits["fat-macho"].verified is True
    assert hits["java-class"].verified is False


def test_scan_is_sorted_by_offset():
    blob = b"junk" + b"%PDF-" + b"\x00" * 8 + b"PK\x03\x04"
    hits = scan(blob)

    offsets = [hit.offset for hit in hits]
    assert offsets == sorted(offsets)
