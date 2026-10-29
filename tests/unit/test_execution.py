"""Unit tests for the dynamic execution substrate."""

from pathlib import Path

import pytest

from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.execution import (
    DryRunExecutor,
    ExecutionRefused,
    ExecutionRequest,
    SandboxSpec,
    SubprocessSandboxExecutor,
    authorize,
    build_plan,
    detect_sandbox,
)


def _config(**extra):
    return RuntimeConfig(extra=extra)


def test_execution_is_denied_without_an_authorization_block(tmp_path):
    target = tmp_path / "lib.so"
    target.write_bytes(b"x")

    result = authorize(_config(), target)

    assert result.granted is False
    assert "dynamic_execution" in result.reason


def test_execution_is_denied_when_not_authorized_explicitly(tmp_path):
    target = tmp_path / "lib.so"
    target.write_bytes(b"x")

    result = authorize(_config(dynamic_execution={"authorized": False}), target)

    assert result.granted is False


def test_execution_is_granted_with_an_explicit_flag(tmp_path):
    target = tmp_path / "lib.so"
    target.write_bytes(b"x")

    result = authorize(_config(dynamic_execution={"authorized": True}), target)

    assert result.granted is True
    assert result.allow_listed is True


def test_allow_list_restricts_granted_targets(tmp_path):
    allowed = tmp_path / "allowed.so"
    other = tmp_path / "other.so"
    for path in (allowed, other):
        path.write_bytes(b"x")
    config = _config(
        dynamic_execution={"authorized": True, "allow_targets": [str(allowed)]}
    )

    assert authorize(config, allowed).granted is True
    denied = authorize(config, other)
    assert denied.granted is False
    assert "allow_targets" in denied.reason


def test_sandbox_detection_prefers_bwrap(monkeypatch):
    monkeypatch.setattr(
        "soinsight.infrastructure.execution.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"bwrap", "unshare"} else None,
    )

    sandbox = detect_sandbox()

    assert sandbox is not None
    assert sandbox.name == "bwrap"


def test_sandbox_detection_falls_back_to_unshare(monkeypatch):
    monkeypatch.setattr(
        "soinsight.infrastructure.execution.shutil.which",
        lambda name: "/usr/bin/unshare" if name == "unshare" else None,
    )

    assert detect_sandbox().name == "unshare"


def test_sandbox_detection_returns_none_without_any_primitive(monkeypatch):
    monkeypatch.setattr(
        "soinsight.infrastructure.execution.shutil.which", lambda name: None
    )

    assert detect_sandbox() is None


def test_plan_wraps_the_command_and_keeps_the_limits(tmp_path):
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap", "--unshare-all"))
    request = ExecutionRequest(
        target=tmp_path / "lib.so",
        argv=("driver", "lib.so"),
        timeout_seconds=7,
        memory_mib=64,
    )

    plan = build_plan(request, sandbox)

    assert plan.argv == (
        "bwrap", "--unshare-all", "--unshare-net", "driver", "lib.so"
    )
    assert plan.sandbox == "bwrap"
    assert plan.timeout_seconds == 7
    assert plan.memory_mib == 64
    assert plan.allow_network is False


def test_plan_unshares_the_network_for_bwrap_when_not_allowed(tmp_path):
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap",))
    request = ExecutionRequest(
        target=tmp_path / "lib.so", argv=("driver",), allow_network=False
    )

    plan = build_plan(request, sandbox)

    assert plan.argv == ("bwrap", "--unshare-net", "driver")


def test_dry_run_executor_plans_but_never_runs(tmp_path):
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap",))
    executor = DryRunExecutor(sandbox)
    request = ExecutionRequest(target=tmp_path / "lib.so", argv=("driver",))

    plan = executor.plan(request)

    assert plan.argv == ("bwrap", "--unshare-net", "driver")
    with pytest.raises(ExecutionRefused):
        executor.run(request)


def test_subprocess_executor_requires_an_explicit_opt_in(tmp_path, monkeypatch):
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap",))
    request = ExecutionRequest(target=tmp_path / "lib.so", argv=("driver",))
    executor = SubprocessSandboxExecutor(sandbox)

    with pytest.raises(ExecutionRefused):
        executor.run(request)


def test_subprocess_executor_uses_the_plan_when_allowed(tmp_path, monkeypatch):
    import subprocess

    recorded = {}

    class _Completed:
        returncode = 0
        stdout = "out"
        stderr = ""

    def fake_run(argv, **kwargs):
        recorded["argv"] = argv
        recorded.update(kwargs)
        return _Completed()

    monkeypatch.setattr(subprocess, "run", fake_run)
    sandbox = SandboxSpec(name="bwrap", prefix=("bwrap",))
    request = ExecutionRequest(
        target=tmp_path / "lib.so", argv=("driver", "lib.so"), timeout_seconds=5
    )

    outcome = SubprocessSandboxExecutor(sandbox, allow_execution=True).run(request)

    assert tuple(recorded["argv"]) == ("bwrap", "--unshare-net", "driver", "lib.so")
    assert recorded["timeout"] == 5
    assert outcome.executed is True
    assert outcome.stdout == "out"
