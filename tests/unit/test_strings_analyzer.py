"""Unit tests for the advanced.strings analyzer and its extraction basics."""

import base64
import json

from soinsight.analyzers.advanced import AdvancedStringsAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.strings import (
    SENSITIVE_PATTERNS,
    classify_string,
    extract_strings,
)

from tests.conftest import build_elf64_with_symbols


def _target(path, size):
    return AnalysisTarget(
        path=path, real_path=path, name=path.name, size=size, sha256="digest"
    )


def _analyze(tmp_path, blob, name="libsample.so", **extra):
    path = tmp_path / name
    path.write_bytes(blob)
    target = AnalysisTarget(
        path=path, real_path=path, name=name, size=len(blob), sha256="digest"
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedStringsAnalyzer().analyze(target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "strings"
    )
    assert AdvancedStringsAnalyzer.metadata.id == capability.id


def test_extractor_keeps_offsets_and_occurrences():
    data = b"\x01bin\x00\xff" + b"abcd\x00" + b"efgh\x00" + b"abcd\x00" + b"\x01\x02"

    extraction = extract_strings(data, min_length=4)

    assert [entry.value for entry in extraction.entries] == ["abcd", "efgh"]
    assert extraction.entries[0].occurrences == 2
    assert extraction.entries[0].offset == 6
    assert extraction.occurrence_count == 3
    assert extraction.unique_count == 2
    assert extraction.truncated is False


def test_extractor_filters_short_runs():
    extraction = extract_strings(b"abc\x00abcd\x00ab", min_length=4)
    assert [entry.value for entry in extraction.entries] == ["abcd"]


def test_extractor_respects_max_entries_with_full_totals():
    blob = b"".join(b"name_%03d\x00" % index for index in range(10))
    extraction = extract_strings(blob, min_length=4, max_entries=3)

    assert len(extraction.entries) == 3
    assert extraction.unique_count == 10
    assert extraction.truncated is True
    assert extraction.occurrence_count == 10


def test_analyzer_classifies_url_sensitive_and_base64(tmp_path):
    secret = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"
    payload = base64.b64encode(b"shell command: cat /etc/passwd").decode()
    blob = (
        b"\x00"
        + "https://api.example.com/v1/login".encode()
        + b"\x00"
        + secret.encode()
        + b"\x00"
        + "password=hunter2-strength".encode()
        + b"\x00"
        + payload.encode()
        + b"\x00"
    )

    result = _analyze(tmp_path, blob)

    assert result.status == AnalysisStatus.SUCCESS
    classified = result.data["classified"]
    urls = classified["url"]
    assert urls["count"] == 1
    assert urls["hits"][0]["value"] == "https://api.example.com/v1/login"
    assert classified["sensitive"]["count"] == 2
    labels = {hit["label"] for hit in classified["sensitive"]["hits"]}
    assert labels == {"Google API Key", "Password/Token"}
    assert classified["base64"]["count"] == 1


def test_analyzer_decodes_base64_with_preview(tmp_path):
    payload = base64.b64encode(b"printable preview payload").decode()
    result = _analyze(tmp_path, (payload + "\x00").encode())

    hits = result.data["classified"]["base64"]["hits"]
    assert len(hits) == 1
    assert hits[0]["decoded"] == "printable preview payload"


def test_analyzer_rejects_undecodable_base64_candidates(tmp_path):
    result = _analyze(tmp_path, b"A" * 40)

    assert result.data["classified"]["base64"]["count"] == 0


def test_analyzer_reports_strings_with_offsets_and_occurrences(tmp_path):
    blob = b"repeat\x00\x01\x02repeat\x00alpha"
    result = _analyze(tmp_path, blob)

    values = [
        (record["value"], record["occurrences"]) for record in result.data["strings"]
    ]
    assert ("repeat", 2) in values
    assert ("alpha", 1) in values
    assert result.data["counts"]["total_strings"] == 3
    assert result.data["counts"]["unique_strings"] == 2
    assert result.data["counts"]["strings_reported"] == 2


def test_analyzer_reports_empty_input_without_strings(tmp_path):
    result = _analyze(tmp_path, b"\x01\x02\x03")

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["counts"] == {
        "unique_strings": 0,
        "total_strings": 0,
        "strings_reported": 0,
    }
    for category in ("url", "sensitive", "base64"):
        assert result.data["classified"][category]["count"] == 0


def test_analyzer_truncates_string_list_with_diagnostic(tmp_path):
    blob = b"".join(b"distinct%02d\x00" % index for index in range(20))
    result = _analyze(
        tmp_path, blob, capability_options={"advanced.strings": {"max_strings": 5}}
    )

    assert len(result.data["strings"]) == 5
    assert result.data["counts"]["unique_strings"] == 20
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "STRINGS_TRUNCATED" in codes


def test_analyzer_truncates_classified_hits_per_category(tmp_path):
    blob = b"".join(
        "https://host%d.example.com/x\x00".encode() % (index,)
        for index in range(3)
    )
    result = _analyze(
        tmp_path,
        blob,
        capability_options={"advanced.strings": {"max_hits_per_category": 2}},
    )

    urls = result.data["classified"]["url"]
    assert urls["count"] == 3
    assert len(urls["hits"]) == 2
    assert urls["truncated"] is True


def test_analyzer_honors_min_length_option(tmp_path):
    blob = b"sh\x00st\x00short\x00"
    result = _analyze(
        tmp_path, blob, capability_options={"advanced.strings": {"min_length": 5}}
    )

    assert [record["value"] for record in result.data["strings"]] == ["short"]


def test_analyzer_falls_back_for_invalid_options(tmp_path):
    result = _analyze(
        tmp_path,
        b"sample-string",
        capability_options={"advanced.strings": {"min_length": "bogus"}},
    )

    assert result.data["min_length"] == 4


def test_analyzer_scans_only_a_head_when_file_is_huge(tmp_path):
    blob = b"head-string\x00" + b"\x7f" * 4096 + b"tail-string\x00"
    result = _analyze(
        tmp_path, blob, capability_options={"advanced.strings": {"max_scan_bytes": 20}}
    )

    assert result.data["scan_truncated"] is True
    assert result.data["scanned_bytes"] == 20
    assert [record["value"] for record in result.data["strings"]] == ["head-string"]
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert codes == ["STRINGS_INPUT_TRUNCATED"]


def test_analyzer_can_disable_classification(tmp_path):
    result = _analyze(
        tmp_path,
        b"https://clear.endpoint\x00",
        capability_options={"advanced.strings": {"classify": False}},
    )

    classified = result.data["classified"]
    assert all(
        classified[category]["count"] == 0 for category in ("url", "sensitive", "base64")
    )
    assert [record["value"] for record in result.data["strings"]] == [
        "https://clear.endpoint"
    ]


def test_analyzer_attributes_strings_to_elf_sections(tmp_path):
    secret = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"
    extra = {".rodata": secret.encode() + b"\x00"}
    blob = build_elf64_with_symbols(
        [("", 0, 3, 0xFFF1, 0, 0)], with_symtab=False, extra_sections=extra
    )
    result = _analyze(tmp_path, blob)

    hits = result.data["classified"]["sensitive"]["hits"]
    assert len(hits) == 1
    assert hits[0]["section"] == ".rodata"


def test_analyzer_handles_non_elf_targets(tmp_path):
    result = _analyze(tmp_path, b"a plain text file has strings\x00", name="notes.txt")

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["strings"][0]["section"] is None


def test_analyzer_result_is_json_serializable(tmp_path):
    blob = b"https://api.example.com\x00AIzaSyA1234567890abcdefghijklmnopqrstuvw\x00"
    result = _analyze(tmp_path, blob)

    payload = json.dumps(result.data)
    assert "classified" in payload


def test_sensitive_pattern_table_keeps_v1_keys():
    assert set(SENSITIVE_PATTERNS) == {
        "Google API Key",
        "OpenAI Key",
        "GitHub Token",
        "JWT",
        "Password/Token",
    }


def test_classify_string_reports_url_inside_credential_line():
    facts = classify_string("token: sk-proj-testvalue https://callback.example")

    categories = {fact.category for fact in facts}
    assert categories == {"url", "sensitive"}


def test_classify_string_skips_oversized_input():
    assert classify_string("A" * 5000) == ()


def test_classify_string_extracts_the_url_substring():
    facts = classify_string("visit https://picachu.example/now please")

    assert facts[0].category == "url"
    assert facts[0].value == "https://picachu.example/now"
