"""Unit tests for baseline suppression and the CI gate."""

import json
from pathlib import Path

import pytest

from soinsight.application.baseline import (
    BASELINE_VERSION,
    BaselineError,
    apply_baseline,
    gate_failure,
    load_baseline,
    parse_threshold,
    save_baseline,
)
from soinsight.core.models import Confidence, Finding, Severity


def _finding(rule_id: str = "security.dangerous-api.system", severity=Severity.HIGH):
    return Finding(
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        category="dangerous-api",
        severity=severity,
        confidence=Confidence.HIGH,
        message="message",
        fingerprint=f"fp:{rule_id}",
    )


def test_baseline_round_trips_and_suppresses(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    findings = [_finding(), _finding("security.hardening.relro")]

    save_baseline(baseline_path, findings)
    baseline = load_baseline(baseline_path)
    suppressed = apply_baseline([_finding(), _finding("other")], baseline)

    assert len(baseline) == 2
    assert suppressed[0].suppressed is True
    assert suppressed[1].suppressed is False


def test_baseline_file_shape_is_stable(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    save_baseline(baseline_path, [_finding()])

    payload = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert payload["version"] == BASELINE_VERSION
    assert payload["fingerprints"] == ["fp:security.dangerous-api.system"]


def test_finding_without_fingerprint_falls_back_to_rule_and_title(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    no_fp = Finding(
        rule_id="security.x",
        title="Title",
        category="c",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        message="m",
    )
    save_baseline(baseline_path, [no_fp])
    baseline = load_baseline(baseline_path)

    assert apply_baseline([no_fp], baseline)[0].suppressed is True


def test_missing_baseline_is_an_error(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "nope.json")


def test_malformed_baseline_is_an_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(bad)

    wrong_version = tmp_path / "v.json"
    wrong_version.write_text(
        json.dumps({"version": 99, "fingerprints": []}), encoding="utf-8"
    )
    with pytest.raises(BaselineError):
        load_baseline(wrong_version)

    bad_shape = tmp_path / "shape.json"
    bad_shape.write_text(
        json.dumps({"version": 1, "fingerprints": "nope"}), encoding="utf-8"
    )
    with pytest.raises(BaselineError):
        load_baseline(bad_shape)


def test_gate_reports_the_worst_unsuppressed_finding():
    low = _finding("a", Severity.LOW)
    high = _finding("b", Severity.HIGH)
    suppressed_critical = Finding(
        rule_id="c",
        title="suppressed",
        category="c",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        message="m",
        fingerprint="fp:c",
        suppressed=True,
    )

    assert gate_failure([low], Severity.HIGH) is None
    assert gate_failure([low, high], Severity.MEDIUM) is high
    # A suppressible critical finding does not fail the gate.
    assert gate_failure([low, suppressed_critical], Severity.HIGH) is None


def test_threshold_parsing():
    assert parse_threshold("HIGH") is Severity.HIGH
    assert parse_threshold(" low ") is Severity.LOW
    with pytest.raises(BaselineError):
        parse_threshold("catastrophic")
