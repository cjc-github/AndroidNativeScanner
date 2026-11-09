"""End-to-end test of the source-to-sink taint path.

The image is assembled so that the path is unambiguous: a function calls a
source function, copies its return value into the first argument register
and calls a sink with it.
"""

import struct
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from pathlib import Path

from tests.conftest import build_elf64_with_symbols

# The calls target the PLT stubs: 0x1000 -> 0x1020 (getenv), 0x1008 -> 0x1030
# (system). The relative displacement is measured from the next instruction.
CODE = (
    b"\xe8\x1b\x00\x00\x00"        # 0x1000 call 0x1020
    + b"\x48\x89\xc7"              # 0x1005 mov rdi, rax
    + b"\xe8\x23\x00\x00\x00"      # 0x1008 call 0x1030
    + b"\xc3"                      # 0x100d ret
    + b"\x90" * 0xF0
)

# The two lazy stubs: each jumps through its GOT slot.
#   0x1020: jmp qword ptr [rip + 0x0a]  -> GOT 0x1030
#   0x1030: jmp qword ptr [rip + 0x0a]  -> GOT 0x1040
STUBS = (
    b"\xff\x25\x0a\x00\x00\x00" + b"\x90" * 0xA   # 0x1020
    + b"\xff\x25\x0a\x00\x00\x00" + b"\x90" * 0xA   # 0x1030
)

# The symbol table: getenv and system are imported (undefined), handler is
# defined at 0x1000.
SYMBOLS = (
    ("handler", 1, 2, 1, 0x1000, 0x20),
    ("getenv", 1, 2, 0, 0, 0),
    ("system", 1, 2, 0, 0, 0),
)

# The relocations claim the GOT slots: slot 0x1030 -> symbol 1 (getenv),
# slot 0x1040 -> symbol 2 (system). The symbol index counts the entries of
# the dynamic symbol table, starting at one.
RELOCATIONS = (
    struct.pack("<QQq", 0x1030, 1 << 32 | 7, 0)
    + struct.pack("<QQq", 0x1040, 2 << 32 | 7, 0)
)


def build(tmp_path: Path) -> Path:
    """An image whose PLT resolves getenv and system."""
    blob = build_elf64_with_symbols(
        SYMBOLS,
        text_bytes=CODE,
        plt_bytes=STUBS,
        plt_address=0x1020,
        rela_plt_bytes=RELOCATIONS,
    )
    path = tmp_path / "taint.so"
    path.write_bytes(blob)
    return path


def _analyse(path: Path, extra=None):
    from soinsight.analyzers import register_builtin_analyzers
    from soinsight.core.analyzer.registry import AnalyzerRegistry
    from soinsight.core.models import AnalysisTarget
    from soinsight.core.runtime import AnalysisRuntime
    from soinsight.infrastructure.config import RuntimeConfig

    target = AnalysisTarget(
        path=path,
        real_path=path,
        name=path.name,
        size=path.stat().st_size,
        sha256="test",
    )
    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    return AnalysisRuntime(registry).execute(
        target=target,
        analyzer_ids=(
            "basic.symbols",
            "basic.callgraph",
            "basic.dataflow",
            "security.dangerous-api",
            "security.vulnerability",
        ),
        config=RuntimeConfig(extra=extra or {}),
    )


def test_the_source_to_sink_path_is_found(tmp_path):
    """getenv's result reaches system(), so the path must be reported."""
    path = build(tmp_path)
    result = _analyse(path)

    dataflow = result.results["basic.dataflow"].data
    sources = [
        record
        for function in dataflow.get("functions", [])
        for record in function.get("taint_flows", [])
        if record["kind"].startswith("source")
    ]
    assert sources, "the source call was not recognized"
    assert sources[0]["origin"] == "getenv"

    vulnerability = result.results["security.vulnerability"]
    assert vulnerability.data["taint_path_count"] == 1
    assert vulnerability.data["taint_sources"] == ["getenv"]
    assert vulnerability.data["taint_sinks"] == ["system"]

    finding = vulnerability.findings[0]
    evidence = finding.evidence[0]
    assert evidence["taint_source"] == "getenv"
    assert evidence["taint_chain"] == "getenv() -> handler() -> system()"
    assert evidence["taint_path"]["call_site"] == "0x1008"
    assert evidence["taint_path"]["register"] == "rdi"
    assert evidence["taint_path"]["cwe"] == "CWE-78"


def test_a_custom_library_replaces_the_builtin_one(tmp_path):
    """The user may point the analysis at their own source and sink table."""
    library = tmp_path / "custom.yaml"
    library.write_text(
        "version: 1\n"
        "sources:\n"
        "  - name: my_source\n"
        "    match: ^getenv$\n"
        "    kind: return\n"
        "sinks:\n"
        "  - name: my_sink\n"
        "    match: ^system$\n"
        "    kind: argument\n"
        "    argument: 0\n"
        "    cwe: CWE-999\n"
        "    severity: critical\n",
        encoding="utf-8",
    )

    path = build(tmp_path)
    result = _analyse(
        path,
        extra={
            "capability_options": {
                "basic.dataflow": {"taint_library": str(library)},
            }
        },
    )

    vulnerability = result.results["security.vulnerability"]
    assert vulnerability.data["taint_sources"] == ["my_source"]
    assert vulnerability.data["taint_sinks"] == ["my_sink"]
    assert vulnerability.data["taint_path_count"] == 1


def test_a_library_without_the_source_finds_nothing(tmp_path):
    """The table is what decides: without the source there is no path."""
    library = tmp_path / "empty.yaml"
    library.write_text(
        "version: 1\nsources: []\nsinks: []\n",
        encoding="utf-8",
    )

    path = build(tmp_path)
    result = _analyse(
        path,
        extra={
            "capability_options": {
                "basic.dataflow": {"taint_library": str(library)},
            }
        },
    )

    vulnerability = result.results["security.vulnerability"]
    assert vulnerability.data["taint_path_count"] == 0


def test_a_missing_library_is_a_warning_not_a_failure(tmp_path):
    path = build(tmp_path)
    result = _analyse(
        path,
        extra={
            "capability_options": {
                "basic.dataflow": {"taint_library": str(tmp_path / "nope.yaml")},
            }
        },
    )

    dataflow = result.results["basic.dataflow"]
    codes = [item.code for item in dataflow.diagnostics]
    assert "DATAFLOW_TAINT_LIBRARY_INVALID" in codes
    # The rest of the data-flow facts are still valid.
    assert dataflow.status.value == "success"
    assert dataflow.data["function_count"] > 0
