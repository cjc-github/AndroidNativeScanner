"""Unit tests for the taint pass and its use by the security analyzers."""

from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Finding,
    Severity,
)
from soinsight.infrastructure.cfg import build_cfg
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.dataflow import (
    argument_sources,
    propagate_taint,
)

# A small x86-64 function that moves its first argument and calls out.
_X86_CODE = (
    b"\x48\x89\xfe"          # 0x1000 mov rsi, rdi
    + b"\xe8\xfb\x0f\x00\x00"  # 0x1003 call 0x2003
    + b"\xc3"                 # 0x1008 ret
    + b"\x90" * 0xF0
)


def _flow(records, arch="x86-64", **kwargs):
    return propagate_taint(records, build_cfg(records), arch, **kwargs)


def test_argument_sources_follow_the_calling_convention():
    assert argument_sources("x86-64")[:2] == ("rdi", "rsi")
    assert argument_sources("aarch64")[:2] == ("x0", "x1")


def test_the_stack_and_frame_pointers_are_not_argument_sources():
    """A taint that starts at rsp/rbp says nothing about the caller."""
    for arch in ("x86-64", "aarch64"):
        sources = argument_sources(arch)
        assert "rsp" not in sources
        assert "rbp" not in sources
        assert "sp" not in sources


def test_the_bit_width_selects_the_x86_argument_registers():
    """The decoder reports ``x86`` for both widths, so the width decides."""
    assert argument_sources("x86", is64=True)[:2] == ("rdi", "rsi")
    # The 32-bit convention passes arguments on the stack instead.
    assert argument_sources("x86", is64=False) == ()


def test_a_value_copied_from_an_argument_stays_tainted():
    records = [
        (0x1000, 3, "mov", "rsi, rdi"),
        (0x1003, 3, "mov", "rax, rsi"),
    ]

    result = _flow(records)

    targets = {item.target for item in result.records}
    assert "rsi" in targets
    assert "rax" in targets


def test_overwriting_an_argument_kills_its_taint():
    records = [
        (0x1000, 3, "mov", "edi, 1"),
        (0x1003, 3, "mov", "rsi, rdi"),
    ]

    result = _flow(records)

    assert result.records == ()


def test_a_call_consumes_the_tainted_argument_registers():
    records = [
        (0x1000, 3, "mov", "rsi, rdi"),
        (0x1003, 5, "call", "0x2000"),
    ]

    result = _flow(records)

    call_records = [item for item in result.records if item.kind == "call-argument"]
    assert call_records
    assert {item.target for item in call_records} >= {"rdi", "rsi"}
    # The copy of rdi into rsi is handed over as well.
    assert any(
        item.source == "rdi" and item.target == "rsi" for item in call_records
    )


def test_a_call_kills_the_taint_of_the_caller_saved_registers():
    records = [
        (0x1000, 3, "mov", "rsi, rdi"),
        (0x1003, 5, "call", "0x2000"),
        (0x1008, 3, "mov", "rax, rsi"),
    ]

    result = _flow(records)

    # ``rsi`` is caller-saved, so the copy after the call is not tainted.
    assert "rax" not in {item.target for item in result.records}


def test_a_store_through_a_pointer_does_not_kill_the_pointer():
    records = [
        (0x1000, 3, "mov", "rsi, rdi"),
        (0x1003, 4, "mov", "qword ptr [rdi], rax"),
        (0x1007, 5, "call", "0x2000"),
    ]

    result = _flow(records)

    # The pointer was only read, so its taint survives the store and the call
    # still receives a tainted argument.
    call_records = [item for item in result.records if item.kind == "call-argument"]
    assert "rdi" in {item.target for item in call_records}


def test_the_taint_depth_is_capped():
    records = [(0x1000, 3, "mov", "rsi, rdi")]
    for index in range(6):
        address = 0x1003 + index * 3
        records.append((address, 3, "mov", f"r{index + 10}, rsi" if index == 0 else f"r{index + 10}, r{index + 9}"))

    result = _flow(records, max_depth=1)

    assert all(item.depth <= 1 for item in result.records)


def _context(**options):
    target = AnalysisTarget(
        path=None, real_path=None, name="libsample.so", size=0, sha256="test"
    )
    return AnalysisContext("run", target, RuntimeConfig(extra=options)), target


def test_the_dataflow_analyzer_reports_the_taint_state(tmp_path):
    from soinsight.analyzers.dataflow import BasicDataflowAnalyzer
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    sample = tmp_path / "sample.so"
    sample.write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=_X86_CODE))
    target = AnalysisTarget(
        path=sample,
        real_path=sample,
        name=sample.name,
        size=sample.stat().st_size,
        sha256="test",
    )
    context = AnalysisContext("run", target, RuntimeConfig())

    result = BasicDataflowAnalyzer().analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["taint"] == "enabled"
    assert result.data["taint_scope"] == "intra-procedural"


def test_the_taint_state_is_disabled_by_option(tmp_path):
    from soinsight.analyzers.dataflow import BasicDataflowAnalyzer
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    sample = tmp_path / "sample.so"
    sample.write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS, text_bytes=_X86_CODE))
    target = AnalysisTarget(
        path=sample,
        real_path=sample,
        name=sample.name,
        size=sample.stat().st_size,
        sha256="test",
    )
    context = AnalysisContext(
        "run",
        target,
        RuntimeConfig(extra={"capability_options": {"basic.dataflow": {"taint": False}}}),
    )

    result = BasicDataflowAnalyzer().analyze(target, context)

    assert result.data["taint"] == "disabled"


def _dangerous_finding():
    return Finding(
        rule_id="security.dangerous-api.system",
        title="Dangerous API",
        category="命令执行",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        message="system",
        fingerprint="dangerous:system",
        evidence=[
            {
                "symbol": "system",
                "canonical_symbol": "system",
                "usage": "import",
                "source": ".dynsym",
                "api_category": "命令执行",
                "evidence_level": "call-site",
                "call_site_count": 1,
                "call_sites": ("0x1010",),
            }
        ],
    )


def _vulnerability_context(with_taint: bool):
    context, target = _context()
    context.add_result(
        AnalysisResult(
            analyzer_id="security.dangerous-api",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"matched_apis": ["system"], "finding_count": 1},
            findings=[_dangerous_finding()],
        )
    )
    if with_taint:
        context.add_result(
            AnalysisResult(
                analyzer_id="basic.dataflow",
                analyzer_version="1.0.0",
                status=AnalysisStatus.SUCCESS,
                data={
                    "functions": [
                        {
                            "name": "danger",
                            "address": "0x1000",
                            "taint_flows": [
                                {
                                    "source": "rdi",
                                    "target": "rdi",
                                    "address": "0x1010",
                                    "depth": 0,
                                    "kind": "call-argument",
                                }
                            ],
                        }
                    ]
                },
            )
        )
    return context, target


def test_the_vulnerability_finding_stays_unchanged_without_taint_evidence():
    from soinsight.analyzers.security import SecurityVulnerabilityAnalyzer

    context, target = _vulnerability_context(with_taint=False)
    result = SecurityVulnerabilityAnalyzer().analyze(target, context)

    finding = result.findings[0]
    assert finding.confidence is Confidence.MEDIUM
    assert not any(
        entry.get("parameter_controllable")
        for entry in finding.evidence
        if isinstance(entry, dict)
    )


def test_a_tainted_call_site_marks_the_finding_parameter_controllable():
    from soinsight.analyzers.security import SecurityVulnerabilityAnalyzer

    context, target = _vulnerability_context(with_taint=True)
    result = SecurityVulnerabilityAnalyzer().analyze(target, context)

    finding = result.findings[0]
    entries = [entry for entry in finding.evidence if isinstance(entry, dict)]
    assert entries[0].get("parameter_controllable") is True
    assert entries[0].get("evidence_level") == "call-site+taint"
    assert entries[0]["taint"][0]["source"] == "rdi"
    # The fingerprint must not change: baselines depend on it.
    assert finding.fingerprint == "vuln:CWE-78:system"
    assert result.data["parameter_controllable_count"] == 1
