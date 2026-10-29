"""Unit tests for the built-in advanced.protocol analyzer."""

from pathlib import Path

from soinsight.analyzers.protocol import AdvancedProtocolAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.protocol import identify


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedProtocolAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="sample.bin"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("advanced").get_capability(
        "protocol"
    )
    assert capability.id == AdvancedProtocolAnalyzer.metadata.id
    assert AdvancedProtocolAnalyzer.metadata.id == "advanced.protocol"


def test_identify_http_from_strings_only():
    report = identify(("GET / HTTP/1.1", "User-Agent: test"), ())

    by_name = {item.protocol: item for item in report.protocols}
    assert "http" in by_name
    assert by_name["http"].strength == "corroborated"


def test_identify_tls_from_symbols_only():
    report = identify(("plain text",), ("SSL_CTX_new", "SSL_read"))

    by_name = {item.protocol: item for item in report.protocols}
    tls = by_name["tls"]
    assert tls.strength == "single"
    sources = {ev.source for ev in tls.evidence}
    assert sources == {"symbol"}


def test_identify_https_corroborates_with_symbols():
    report = identify(("https://example.com",), ("SSL_read", "SSL_CTX_new"))

    by_name = {item.protocol: item for item in report.protocols}
    assert by_name["https"].strength == "corroborated"


def test_analyzer_reports_protocols_from_a_blob(tmp_path):
    blob = b"plain GET / HTTP/1.1 tail MQTT connect" + b"\x00" * 8
    result = _analyze(_write(tmp_path, blob, "blob.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    protocols = {item["protocol"] for item in result.data["protocols"]}
    assert "http" in protocols
    assert "mqtt" in protocols


def test_unknown_blob_reports_no_protocols(tmp_path):
    blob = b"\x00" * 64 + b"nothing recognizable here" + b"\x00" * 16
    result = _analyze(_write(tmp_path, blob, "plain.bin"))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["protocol_count"] == 0


def test_input_larger_than_cap_warns(tmp_path):
    blob = b"\x00" * 70000
    result = _analyze(_write(tmp_path, blob, "big.bin"), capability_options={
        "advanced.protocol": {"max_scan_bytes": 100}
    })

    assert result.data["scan_truncated"] is True
    codes = [d.code for d in result.diagnostics]
    assert "PROTOCOL_INPUT_TRUNCATED" in codes


def test_format_text_reports_the_summary(tmp_path):
    blob = b"GET / HTTP/1.1"
    result = _analyze(_write(tmp_path, blob, "blob.bin"))
    text = AdvancedProtocolAnalyzer().format_text(result)

    assert "协议识别" in text
    assert "http" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze(_write(tmp_path, b"plain", "x.bin"))
    result.status = AnalysisStatus.FAILED

    assert AdvancedProtocolAnalyzer().format_text(result) is None
