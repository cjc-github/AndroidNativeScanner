"""Integration tests for the taint library option on the command line."""

import json
import struct
from io import StringIO

from soinsight.cli.main import main

from tests.conftest import build_elf64_with_symbols


# The two lazy stubs: each jumps through its GOT slot.
#   0x1020 -> GOT 0x1030 (the first import)
#   0x1030 -> GOT 0x1040 (the second import)
STUBS = (
    b"\xff\x25\x0a\x00\x00\x00" + b"\x90" * 0xA   # 0x1020
    + b"\xff\x25\x0a\x00\x00\x00" + b"\x90" * 0xA   # 0x1030
)

# Two imported functions and one defined function.
SYMBOLS = (
    ("handler", 1, 2, 1, 0x1000, 0x20),
    ("getenv", 1, 2, 0, 0, 0),
    ("system", 1, 2, 0, 0, 0),
)

RELOCATIONS = (
    struct.pack("<QQq", 0x1030, 1 << 32 | 7, 0)
    + struct.pack("<QQq", 0x1040, 2 << 32 | 7, 0)
)

# The handler calls getenv through the stub at 0x1020 and passes the result
# to system through the stub at 0x1030.
CODE = (
    b"\xe8\x1b\x00\x00\x00"        # 0x1000 call 0x1020 (getenv)
    + b"\x48\x89\xc7"              # 0x1005 mov rdi, rax
    + b"\xe8\x23\x00\x00\x00"      # 0x1008 call 0x1030
    + b"\xc3"                      # 0x100d ret
    + b"\x90" * 0xF0
)

# The custom table renames the source and the sink of the built-in one.
LIBRARY = """version: 1
sources:
  - name: my_source
    match: ^getenv$
    kind: return
sinks:
  - name: my_sink
    match: ^system$
    kind: argument
    argument: 0
    cwe: CWE-CUSTOM
    severity: critical
"""


def _sample(tmp_path):
    """A real ELF whose PLT resolves getenv and system."""
    path = tmp_path / "sample.so"
    path.write_bytes(
        build_elf64_with_symbols(
            SYMBOLS,
            text_bytes=CODE,
            plt_bytes=STUBS,
            plt_address=0x1020,
            rela_plt_bytes=RELOCATIONS,
        )
    )
    return path


def test_the_scan_accepts_a_taint_library(tmp_path):
    library = tmp_path / "taint.yaml"
    library.write_text(LIBRARY, encoding="utf-8")
    target = _sample(tmp_path)
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(target),
            "--enable", "basic.symbols",
            "--enable", "basic.callgraph",
            "--enable", "basic.dataflow",
            "--enable", "security.dangerous-api",
            "--enable", "security.vulnerability",
            "--taint-library", str(library),
            "--format", "json",
            "--no-cache",
        ],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    results = payload["result"]["results"]

    # The custom table is the one in effect. The built-in table has neither
    # ``my_source`` nor ``my_sink``, so the analyzer can only report those
    # names if it read the custom file.
    data = results["security.vulnerability"]["data"]
    assert data["taint_sources"] == ["my_source"]
    assert data["taint_sinks"] == ["my_sink"]
    assert data["taint_path_count"] == 1

    # The finding carries the custom CWE and severity.
    findings = results["security.vulnerability"]["findings"]
    tainted = [
        finding
        for finding in findings
        if finding["rule_id"].endswith("taint.my_sink")
    ]
    assert tainted, [finding["rule_id"] for finding in findings]
    assert tainted[0]["severity"] == "critical"


def test_the_scan_reports_a_missing_library(tmp_path):
    target = _sample(tmp_path)
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(target),
            "--enable", "basic.dataflow",
            "--taint-library", str(tmp_path / "nope.yaml"),
            "--format", "json",
            "--no-cache",
        ],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    result = payload["result"]["results"]["basic.dataflow"]
    codes = [item["code"] for item in result["diagnostics"]]
    assert "DATAFLOW_TAINT_LIBRARY_INVALID" in codes
    # The rest of the analysis is unaffected.
    assert result["status"] == "success"
