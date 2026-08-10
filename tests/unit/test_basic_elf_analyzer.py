"""Unit tests for the built-in ELF header analyzer."""

from pathlib import Path

from soinsight.analyzers.basic import BasicElfAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig


def _target(path: Path) -> AnalysisTarget:
    data = path.read_bytes()
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=len(data),
        sha256="test-sha256",
    )


def test_basic_elf_analyzer_parses_minimal_elf64_header(tmp_path, minimal_elf64_little):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(minimal_elf64_little)
    analyzer = BasicElfAnalyzer()
    target = _target(sample)
    context = AnalysisContext("run", target, RuntimeConfig())

    result = analyzer.analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "basic.elf"
    assert result.data == {
        "elf_class": "ELF64",
        "endianness": "little",
        "type": "DYN",
        "machine": "x86-64",
        "entry_point": "0x401000",
        "program_header_count": 8,
        "section_header_count": 12,
    }


def test_basic_elf_analyzer_rejects_non_elf(tmp_path):
    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"not an elf file at all")
    analyzer = BasicElfAnalyzer()
    target = _target(sample)
    context = AnalysisContext("run", target, RuntimeConfig())

    result = analyzer.analyze(target, context)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_basic_elf_analyzer_rejects_truncated_elf_header(tmp_path):
    sample = tmp_path / "truncated.so"
    sample.write_bytes(b"\x7fELF" + bytes(30))  # valid magic but header < 52 bytes
    analyzer = BasicElfAnalyzer()
    target = _target(sample)
    context = AnalysisContext("run", target, RuntimeConfig())

    result = analyzer.analyze(target, context)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def _elf64_header_with(type_: int, machine: int) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = (
        type_.to_bytes(2, "little")
        + machine.to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (0x401000).to_bytes(8, "little")
        + (64).to_bytes(8, "little")
        + (1024).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + (8).to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + (12).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
    )
    return ident + header


def test_basic_elf_analyzer_degrades_unknown_type_and_machine(tmp_path):
    sample = tmp_path / "unknown.so"
    sample.write_bytes(_elf64_header_with(type_=99, machine=999))
    analyzer = BasicElfAnalyzer()
    target = _target(sample)
    context = AnalysisContext("run", target, RuntimeConfig())

    result = analyzer.analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["type"] == "99"
    assert result.data["machine"] == "999"
