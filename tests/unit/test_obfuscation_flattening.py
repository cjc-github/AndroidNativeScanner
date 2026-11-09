"""Unit tests for control-flow flattening detection in advanced.obfuscation."""

from pathlib import Path

from soinsight.analyzers.obfuscation import AdvancedObfuscationAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.cfg import build_cfg
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.obfuscation import scan_control_flow


def _function_of(records, name: str = "f") -> dict:
    """Turn an instruction stream into the dict the CFG analyzer produces."""
    graph = build_cfg(sorted(records))
    return {
        "name": name,
        "address": hex(graph.entry or 0),
        "size": 0x100,
        "source": "symbols",
        "instruction_count": len(records),
        "block_count": graph.block_count,
        "edge_count": graph.edge_count,
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
        "edges": [],
        "loops": [],
    }


def _flattened_function(states: int = 10) -> dict:
    """The flattened shape: every state ends in an indirect jump.

    A flattened function dispatches through a table, so the state blocks end
    in a jump whose destination is not in the instruction text. The CFG is
    therefore cut at every state, which is exactly what the detector keys on.
    """
    records = []
    address = 0x1000
    for _ in range(states):
        records.append((address, 3, "mov", "eax, ebx"))
        records.append((address + 3, 3, "jmp", "rax"))
        address += 16
    return _function_of(records, "flattened")


def _ordinary_function() -> dict:
    """A plain function: direct branches, so the CFG stays connected."""
    records = [(0x1000 + index * 4, 4, "add", "eax, ebx") for index in range(20)]
    records.append((0x1080, 2, "jmp", "0x1000"))
    records.append((0x1082, 1, "ret", ""))
    return _function_of(records, "ordinary")


def _few_indirect_function() -> dict:
    """Ordinary code with a single indirect jump: not a state machine."""
    records = [(0x1000 + index * 4, 4, "add", "eax, ebx") for index in range(10)]
    records.append((0x1028, 3, "jmp", "rax"))
    records.append((0x102b, 1, "ret", ""))
    return _function_of(records, "few-indirect")


def _analyze_with_cfg(path: Path, functions, **extra) -> object:
    if not path.exists():
        path.write_bytes(b"plain")
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    context.add_result(
        AnalysisResult(
            analyzer_id="basic.cfg",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"functions": list(functions)},
        )
    )
    return AdvancedObfuscationAnalyzer().analyze(target, context)


def _analyze(path: Path, **extra) -> object:
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return AdvancedObfuscationAnalyzer().analyze(target, context)


def test_a_flattened_graph_is_detected():
    """The detector has to work on a graph the CFG builder really produces."""
    hits = scan_control_flow([_flattened_function()])

    assert [item.signal for item in hits] == ["control-flow-flattening"]
    assert hits[0].category == "obfuscator"
    assert hits[0].strength == "corroborated"


def test_an_ordinary_graph_is_not_flagged():
    hits = scan_control_flow([_ordinary_function()])

    assert hits == ()


def test_a_single_indirect_jump_is_not_enough():
    """One unresolved jump in ordinary code must not read as flattening."""
    hits = scan_control_flow([_few_indirect_function()])

    assert hits == ()


def test_the_evidence_carries_the_measured_numbers():
    hits = scan_control_flow([_flattened_function()])

    joined = " ".join(item.detail for item in hits[0].evidence)
    assert "间接跳转" in joined
    assert "占比" in joined


def test_too_few_blocks_is_not_flagged():
    records = [
        (0x1000, 3, "mov", "eax, ebx"),
        (0x1003, 3, "jmp", "rax"),
        (0x1006, 1, "ret", ""),
    ]
    hits = scan_control_flow([_function_of(records, "small")])

    assert hits == ()


def test_the_analyzer_merges_the_flattening_signal(tmp_path):
    result = _analyze_with_cfg(tmp_path / "sample.so", [_flattened_function()])

    signals = {item["signal"] for item in result.data["signals"]}
    assert "control-flow-flattening" in signals
    assert result.data["flattening_signal_count"] == 1
    assert result.data["flattening_checked"] is True


def test_the_analyzer_reports_when_the_cfg_is_absent(tmp_path):
    result = _analyze(_write(tmp_path))

    codes = [d.code for d in result.diagnostics]
    assert "OBFUSCATION_FLATTENING_UNAVAILABLE" in codes
    assert result.data["flattening_signal_count"] == 0


def test_flattening_can_be_turned_off(tmp_path):
    result = _analyze_with_cfg(
        tmp_path / "sample.so",
        [_flattened_function()],
        capability_options={"advanced.obfuscation": {"flattening": False}},
    )

    signals = {item["signal"] for item in result.data["signals"]}
    assert "control-flow-flattening" not in signals
    assert result.data["flattening_checked"] is False


def test_an_ordinary_cfg_produces_no_flattening_signal(tmp_path):
    result = _analyze_with_cfg(tmp_path / "sample.so", [_ordinary_function()])

    signals = {item["signal"] for item in result.data["signals"]}
    assert "control-flow-flattening" not in signals


def test_the_text_output_names_the_flattening_signal(tmp_path):
    result = _analyze_with_cfg(tmp_path / "sample.so", [_flattened_function()])
    text = AdvancedObfuscationAnalyzer().format_text(result)

    assert "控制流平坦化" in text


def _write(tmp_path, blob=b"plain", name="sample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_a_real_library_is_not_flagged(tmp_path):
    """The detector must not fire on ordinary, un-obfuscated code.

    A regression guard: an earlier criterion (a high in-degree join point)
    fired on 19 of the 124 functions of a real, un-obfuscated library.
    """
    from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

    sample = tmp_path / "sample.so"
    sample.write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS))

    result = _analyze(sample)

    assert result.data["flattening_signal_count"] == 0
