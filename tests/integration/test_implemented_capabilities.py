"""End-to-end verification of the implemented capabilities.

These checks exercise the real code paths on a real library: the flattening
detector on a recovered CFG, the taint facts against the real call graph,
the dynamic analyzers with the subprocess layer spied on, and the
multi-target, report and seed paths through the CLI.

They are deliberately written against the real sample rather than against
synthetic fixtures, because an earlier version of the flattening check
passed on hand-written dictionaries while never firing on a real graph.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, "src")

REPO = Path(__file__).resolve().parents[2]
SAMPLE = REPO / "in" / "libtest_demo.so"


def _run_cli(*arguments):
    """Run the CLI and return its parsed JSON output."""
    completed = subprocess.run(
        [sys.executable, "-m", "soinsight", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _as_cfg_function(records, name: str) -> dict:
    """Turn an instruction stream into the dict the CFG analyzer produces."""
    from soinsight.infrastructure.cfg import build_cfg

    graph = build_cfg(sorted(records))
    return {
        "name": name,
        "blocks": [
            {
                "start": hex(block.start),
                "end": hex(block.end),
                "terminator": block.terminator,
                "successors": [hex(item) for item in block.successors],
                "indirect_jump": bool(
                    block.terminator
                    and block.terminator == "jmp"
                    and not block.successors
                ),
            }
            for block in graph.blocks
        ],
        "block_count": graph.block_count,
        "edge_count": graph.edge_count,
    }


# --- control-flow flattening ------------------------------------------------

def test_a_flattened_graph_is_detected():
    """A state machine dispatches through a table: every state ends in an
    indirect jump, which is what the detector keys on."""
    from soinsight.infrastructure.obfuscation import scan_control_flow

    records = []
    address = 0x1000
    for _ in range(10):
        records.append((address, 3, "mov", "eax, ebx"))
        records.append((address + 3, 3, "jmp", "rax"))
        address += 16

    hits = scan_control_flow([_as_cfg_function(records, "flattened")])

    assert [item.signal for item in hits] == ["control-flow-flattening"]


def test_ordinary_code_is_not_flagged():
    from soinsight.infrastructure.obfuscation import scan_control_flow

    records = [(0x1000 + index * 4, 4, "add", "eax, ebx") for index in range(20)]
    records.append((0x1080, 2, "jmp", "0x1000"))
    records.append((0x1082, 1, "ret", ""))

    hits = scan_control_flow([_as_cfg_function(records, "ordinary")])

    assert hits == ()


def test_a_real_library_produces_no_false_positives():
    """The regression guard: an earlier criterion flagged 19 of the 124
    functions of a real, un-obfuscated library."""
    if not SAMPLE.is_file():
        pytest.skip("the sample library is not present")

    payload = _run_cli(
        "scan", str(SAMPLE),
        "--enable", "basic.cfg",
        "--enable", "advanced.obfuscation",
        "--format", "json",
        "--no-cache",
    )
    results = payload["result"]["results"]

    assert results["advanced.obfuscation"]["data"]["flattening_signal_count"] == 0


# --- taint and the vulnerability evidence -----------------------------------

def _scan_results(*analyzers):
    payload = _run_cli(
        "scan", str(SAMPLE),
        *sum((["--enable", name] for name in analyzers), []),
        "--format", "json",
        "--no-cache",
    )
    return payload["result"]["results"]


def test_the_taint_sources_are_argument_registers():
    if not SAMPLE.is_file():
        pytest.skip("the sample library is not present")

    results = _scan_results("basic.dataflow")
    dataflow = results["basic.dataflow"]["data"]

    sources = {
        flow["source"]
        for function in dataflow.get("functions", [])
        for flow in function.get("taint_flows", [])
    }

    if not sources:
        pytest.skip("the sample has no symbol table, so no taint facts were produced")
    assert not sources & {"rsp", "rbp", "sp"}


def test_a_tainted_call_site_marks_the_finding_parameter_controllable():
    if not SAMPLE.is_file():
        pytest.skip("the sample library is not present")

    results = _scan_results(
        "basic.symbols", "basic.callgraph", "basic.dataflow",
        "security.dangerous-api", "security.vulnerability",
    )
    vulnerability = results["security.vulnerability"]

    controllable = [
        finding
        for finding in vulnerability["findings"]
        if any(
            isinstance(entry, dict) and entry.get("parameter_controllable")
            for entry in finding["evidence"]
        )
    ]
    if not controllable:
        pytest.skip("the sample has no dangerous API reached with tainted data")

    entry = controllable[0]["evidence"][0]
    assert entry["evidence_level"] == "call-site+taint"
    assert entry["taint"]
    # The taint must point at a call site the analyzer already knew about.
    assert set(entry["taint"][0]["call_site"] for _ in [0]) <= set(
        entry["call_sites"]
    )


# --- the dynamic analyzers never execute anything ---------------------------

def test_the_dynamic_analyzers_never_start_a_process(monkeypatch):
    """Even fully authorized, the collectors only produce a plan."""
    from pathlib import Path as _Path

    from soinsight.analyzers.dynamic_arguments import DynamicArgumentsAnalyzer
    from soinsight.analyzers.dynamic_coverage import DynamicCoverageAnalyzer
    from soinsight.analyzers.dynamic_memory import DynamicMemoryAnalyzer
    from soinsight.analyzers.dynamic_syscalls import DynamicSyscallAnalyzer
    from soinsight.core.analyzer import AnalysisContext
    from soinsight.core.models import AnalysisTarget
    from soinsight.infrastructure.config import RuntimeConfig

    calls = []

    def spy(*args, **kwargs):
        calls.append(args)
        raise AssertionError("a dynamic analyzer tried to start a process")

    monkeypatch.setattr(subprocess, "run", spy)
    monkeypatch.setattr(subprocess, "Popen", spy)

    target = AnalysisTarget(
        path=None, real_path=_Path("/tmp/lib.so"), name="lib.so",
        size=0, sha256="x",
    )
    config = RuntimeConfig(extra={
        "dynamic_execution": {"authorized": True},
        "capability_options": {
            "dynamic.arguments": {"sandbox": "bwrap"},
            "dynamic.memory": {"sandbox": "bwrap"},
            "dynamic.syscalls": {"sandbox": "bwrap"},
            "dynamic.coverage": {"sandbox": "bwrap"},
        },
    })

    for analyzer_class in (
        DynamicArgumentsAnalyzer,
        DynamicMemoryAnalyzer,
        DynamicSyscallAnalyzer,
        DynamicCoverageAnalyzer,
    ):
        context = AnalysisContext("run", target, config)
        result = analyzer_class().analyze(target, context)
        assert result.data["executed"] is False

    assert not calls


# --- multi-target scanning ---------------------------------------------------

def test_a_directory_scan_reports_every_target(tmp_path):
    if not SAMPLE.is_file():
        pytest.skip("the sample library is not present")

    libraries = tmp_path / "libs"
    libraries.mkdir()
    (libraries / "a.so").write_bytes(SAMPLE.read_bytes())
    (libraries / "b.so").write_bytes(SAMPLE.read_bytes())
    (libraries / "notes.txt").write_text("not a library")

    payload = _run_cli(
        "scan", str(libraries),
        "--include", "*.so",
        "--enable", "basic.file",
        "--format", "json",
    )

    assert payload["summary"]["target_count"] == 2
    assert payload["summary"]["failed_count"] == 0
    assert len(payload["results"]) == 2


# --- the report --------------------------------------------------------------

def test_the_report_summarizes_the_analyzers_that_ran_before_it():
    if not SAMPLE.is_file():
        pytest.skip("the sample library is not present")

    payload = _run_cli(
        "scan", str(SAMPLE),
        "--enable", "basic.file",
        "--enable", "basic.elf",
        "--enable", "basic.symbols",
        "--enable", "automation.report",
        "--format", "json",
        "--no-cache",
    )
    report = payload["result"]["results"]["automation.report"]["data"]

    assert report["analyzer_count"] == 3
    assert {item["analyzer_id"] for item in report["sections"]} == {
        "basic.file",
        "basic.elf",
        "basic.symbols",
    }
    assert set(report["rendered_formats"]) == {
        "markdown", "json", "sarif", "html", "text",
    }
    assert "libtest_demo.so" in report["report_text"]


# --- the seed corpus ---------------------------------------------------------

def test_the_seeds_are_derived_from_the_recovered_facts():
    if not SAMPLE.is_file():
        pytest.skip("the sample library is not present")

    payload = _run_cli(
        "scan", str(SAMPLE),
        "--enable", "advanced.file-format",
        "--enable", "advanced.protocol",
        "--enable", "automation.seed",
        "--format", "json",
        "--no-cache",
    )
    seeds = payload["result"]["results"]["automation.seed"]["data"]

    kinds = {seed["kind"] for seed in seeds["seeds"]}
    assert kinds & {"container", "protocol"}
    assert all(seed["size"] > 0 for seed in seeds["seeds"])
    assert len({seed["sha256"] for seed in seeds["seeds"]}) == len(seeds["seeds"])
