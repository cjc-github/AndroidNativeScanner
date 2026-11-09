"""Unit tests for the dynamic collector analyzers."""

import pytest

from soinsight.analyzers.dynamic_arguments import DynamicArgumentsAnalyzer
from soinsight.analyzers.dynamic_coverage import DynamicCoverageAnalyzer
from soinsight.analyzers.dynamic_memory import DynamicMemoryAnalyzer
from soinsight.analyzers.dynamic_syscalls import DynamicSyscallAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.dynamic.collector import (
    build_driver_plan,
    dlopen_harness_source,
    resolve_dynamic_gate,
)

ANALYZERS = (
    ("dynamic.arguments", DynamicArgumentsAnalyzer),
    ("dynamic.memory", DynamicMemoryAnalyzer),
    ("dynamic.syscalls", DynamicSyscallAnalyzer),
    ("dynamic.coverage", DynamicCoverageAnalyzer),
)


def _target(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(b"\x7fELF" + b"A" * 64)
    return AnalysisTarget(
        path=sample,
        real_path=sample,
        name=sample.name,
        size=sample.stat().st_size,
        sha256="test",
    )


def _context(target, upstream=None, **extra):
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    for analyzer_id, data in (upstream or {}).items():
        context.add_result(
            AnalysisResult(
                analyzer_id=analyzer_id,
                analyzer_version="1.0.0",
                status=AnalysisStatus.SUCCESS,
                data=data,
            )
        )
    return context


@pytest.mark.parametrize("capability_id,analyzer_class", ANALYZERS)
def test_analyzer_id_matches_the_catalog(capability_id, analyzer_class):
    from soinsight.modules import create_builtin_module_catalog

    module_id, command = capability_id.split(".")
    capability = (
        create_builtin_module_catalog().get(module_id).get_capability(command)
    )
    assert capability.id == analyzer_class.metadata.id


@pytest.mark.parametrize("capability_id,analyzer_class", ANALYZERS)
def test_without_authorization_nothing_is_planned(capability_id, analyzer_class, tmp_path):
    target = _target(tmp_path)
    context = _context(target)

    result = analyzer_class().analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["state"] == "not-authorized"
    assert result.data["plan"] is None
    assert result.data["executed"] is False
    codes = [d.code for d in result.diagnostics]
    assert "DYNAMIC_EXECUTION_NOT_AUTHORIZED" in codes


@pytest.mark.parametrize("capability_id,analyzer_class", ANALYZERS)
def test_authorization_without_a_sandbox_refuses(
    capability_id, analyzer_class, tmp_path
):
    target = _target(tmp_path)
    context = _context(
        target,
        dynamic_execution={"authorized": True},
        capability_options={capability_id: {"sandbox": "none"}},
    )

    result = analyzer_class().analyze(target, context)

    assert result.data["state"] == "no-sandbox"
    assert result.data["plan"] is None
    codes = [d.code for d in result.diagnostics]
    assert "DYNAMIC_SANDBOX_UNAVAILABLE" in codes


@pytest.mark.parametrize("capability_id,analyzer_class", ANALYZERS)
def test_the_allow_list_is_enforced(capability_id, analyzer_class, tmp_path):
    target = _target(tmp_path)
    context = _context(
        target,
        dynamic_execution={
            "authorized": True,
            "allow_targets": [str(tmp_path / "other.so")],
        },
        capability_options={capability_id: {"sandbox": "bwrap"}},
    )

    result = analyzer_class().analyze(target, context)

    assert result.data["state"] == "not-authorized"
    assert result.data["plan"] is None


def test_the_gate_reports_a_plan_when_everything_is_in_place(tmp_path):
    target = _target(tmp_path)
    context = _context(
        target,
        dynamic_execution={"authorized": True},
        capability_options={"dynamic.arguments": {"sandbox": "bwrap"}},
    )

    result = DynamicArgumentsAnalyzer().analyze(target, context)

    if result.data["state"] == "planned":
        plan = result.data["plan"]
        assert plan["sandbox"] == "bwrap"
        assert isinstance(plan["argv"], list)
        assert plan["argv"][0] == "bwrap"
        assert plan["timeout_seconds"] > 0
    else:
        # The host has no bwrap installed; the analyzer must say so instead
        # of pretending it can run.
        assert result.data["state"] == "no-sandbox"
        assert result.data["plan"] is None


def test_the_arguments_collector_lists_the_entry_points(tmp_path):
    target = _target(tmp_path)
    context = _context(
        target,
        {
            "basic.symbols": {
                "functions": [
                    {
                        "name": "parse",
                        "signature": "int parse(const unsigned char *buf, size_t len)",
                        "language": "c",
                        "address": "0x1000",
                        "parameters": [
                            {"index": 0, "name": "buf", "type": "const unsigned char *"},
                            {"index": 1, "name": "len", "type": "size_t"},
                        ],
                    }
                ]
            }
        },
    )

    result = DynamicArgumentsAnalyzer().analyze(target, context)

    assert result.data["entry_point_count"] == 1
    assert result.data["entry_points"][0]["name"] == "parse"
    assert result.data["sampling_points"][0]["points"] == ["arg0", "arg1"]
    assert result.data["entrypoint"] == "parse"


def test_the_memory_collector_always_has_observation_points(tmp_path):
    target = _target(tmp_path)
    context = _context(target)

    result = DynamicMemoryAnalyzer().analyze(target, context)

    kinds = {item["kind"] for item in result.data["observation_points"]}
    assert "region" in kinds


def test_the_syscall_collector_denies_by_default(tmp_path):
    target = _target(tmp_path)
    context = _context(
        target,
        {"security.dangerous-api": {"matched_apis": ["system", "strcpy"]}},
    )

    result = DynamicSyscallAnalyzer().analyze(target, context)

    policy = result.data["policy"]
    assert policy["default_action"] == "deny"
    assert "execve" in policy["blocklist"]
    assert result.data["watched_apis"] == ["system", "strcpy"]


def test_the_coverage_collector_aligns_with_the_cfg(tmp_path):
    target = _target(tmp_path)
    context = _context(
        target,
        {
            "basic.cfg": {
                "functions": [
                    {
                        "name": "main",
                        "blocks": [
                            {
                                "start": "0x1000",
                                "end": "0x1010",
                                "terminator": "ret",
                                "successors": [],
                            }
                        ],
                        "edges": [],
                    }
                ]
            }
        },
    )

    result = DynamicCoverageAnalyzer().analyze(target, context)

    assert result.data["block_count"] == 1
    assert result.data["aligned"] is True
    assert result.data["coverage_map"][0]["id"] == "0x1000"


@pytest.mark.parametrize("capability_id,analyzer_class", ANALYZERS)
def test_the_text_output_names_the_state(capability_id, analyzer_class, tmp_path):
    target = _target(tmp_path)
    context = _context(target)

    result = analyzer_class().analyze(target, context)
    text = analyzer_class().format_text(result)

    assert "动态采集" in text
    assert "not-authorized" in text


def test_the_driver_plan_describes_but_does_not_run():
    spec = build_driver_plan("coverage", "/tmp/lib.so", "main")

    assert spec.kind == "coverage"
    assert spec.driver == "soinsight-coverage-collector"
    assert "main" in spec.arguments
    assert spec.outputs == ("coverage.jsonl",)


def test_an_unknown_collector_kind_is_rejected():
    from soinsight.infrastructure.dynamic.collector import CollectorUnavailable

    with pytest.raises(CollectorUnavailable):
        build_driver_plan("nonsense", "/tmp/lib.so", "main")


def test_the_harness_source_loads_the_library():
    source = dlopen_harness_source("/tmp/lib.so", "parse")

    assert "dlopen" in source
    assert "/tmp/lib.so" in source
    assert "parse" in source
    assert "dlsym" in source


def test_the_gate_refuses_without_an_authorization_block(tmp_path):
    gate = resolve_dynamic_gate(RuntimeConfig(), tmp_path / "lib.so")

    assert gate["state"] == "not-authorized"
    assert gate["plan"] is None
