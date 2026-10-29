"""Unit tests for the gated dynamic.trace analyzer."""

from pathlib import Path

from soinsight.analyzers.dynamic_trace import DynamicTraceAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.execution import SandboxSpec


def _target(path: Path) -> AnalysisTarget:
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )


def _analyze(path: Path, **extra):
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return DynamicTraceAnalyzer().analyze(target, context)


def _write(tmp_path, name="libsample.so"):
    sample = tmp_path / name
    sample.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("dynamic").get_capability("trace")
    assert capability.id == DynamicTraceAnalyzer.metadata.id


def test_without_authorization_nothing_is_planned(tmp_path):
    result = _analyze(_write(tmp_path))

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["executed"] is False
    assert result.data["state"] == "not-authorized"
    assert [d.code for d in result.diagnostics] == ["DYNAMIC_EXECUTION_NOT_AUTHORIZED"]


def test_authorized_without_a_sandbox_refuses_to_run(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soinsight.analyzers.dynamic_trace.detect_sandbox", lambda: None
    )

    result = _analyze(_write(tmp_path), dynamic_execution={"authorized": True})

    assert result.data["executed"] is False
    assert result.data["state"] == "no-sandbox"
    assert [d.code for d in result.diagnostics] == ["DYNAMIC_SANDBOX_UNAVAILABLE"]


def test_authorized_with_a_sandbox_reports_a_plan_only(tmp_path, monkeypatch):
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap", "--unshare-all"))
    monkeypatch.setattr(
        "soinsight.analyzers.dynamic_trace.detect_sandbox", lambda: sandbox
    )

    result = _analyze(_write(tmp_path), dynamic_execution={"authorized": True})

    assert result.data["executed"] is False
    assert result.data["state"] == "planned"
    assert result.data["sandbox"] == "bwrap"
    assert result.data["plan"]["argv"][0] == "bwrap"
    assert result.data["plan"]["argv"][-1].endswith("libsample.so")
    assert [d.code for d in result.diagnostics] == ["DYNAMIC_DRY_RUN"]


def test_allow_list_is_enforced_by_the_analyzer(tmp_path):
    allowed = _write(tmp_path, "allowed.so")
    other = _write(tmp_path, "other.so")

    granted = _analyze(
        allowed,
        dynamic_execution={"authorized": True, "allow_targets": [str(allowed)]},
    )
    denied = _analyze(
        other,
        dynamic_execution={"authorized": True, "allow_targets": [str(allowed)]},
    )

    assert granted.data["state"] != "not-authorized"
    assert denied.data["state"] == "not-authorized"


def test_options_are_clamped_and_applied(tmp_path, monkeypatch):
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap",))
    monkeypatch.setattr(
        "soinsight.analyzers.dynamic_trace.detect_sandbox", lambda: sandbox
    )

    result = _analyze(
        _write(tmp_path),
        dynamic_execution={"authorized": True},
        capability_options={"dynamic.trace": {"timeout_seconds": 0, "memory_mib": "x"}},
    )

    assert result.data["plan"]["timeout_seconds"] == 1
    assert result.data["plan"]["memory_mib"] == 512


def test_format_text_reports_each_state(tmp_path, monkeypatch):
    denied = _analyze(_write(tmp_path))
    denied_text = DynamicTraceAnalyzer().format_text(denied)
    assert "未执行" in denied_text

    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap", "--unshare-all"))
    monkeypatch.setattr(
        "soinsight.analyzers.dynamic_trace.detect_sandbox", lambda: sandbox
    )
    planned = _analyze(_write(tmp_path), dynamic_execution={"authorized": True})
    planned_text = DynamicTraceAnalyzer().format_text(planned)
    assert "执行计划（未启动）" in planned_text
    assert "bwrap" in planned_text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze(_write(tmp_path))
    result.status = AnalysisStatus.FAILED

    assert DynamicTraceAnalyzer().format_text(result) is None
