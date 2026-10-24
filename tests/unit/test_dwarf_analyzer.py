"""Unit tests for the DWARF debug-information analyzer and parser."""

import json

import pytest

from soinsight.analyzers.dwarf import BasicDwarfAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.dwarf import parse_dwarf


def _target(path) -> AnalysisTarget:
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )


def _analyze(path, **extra):
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return BasicDwarfAnalyzer().analyze(target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability("dwarf")
    assert BasicDwarfAnalyzer.metadata.id == capability.id == "basic.dwarf"
    assert BasicDwarfAnalyzer.metadata.requires == ("basic.elf",)


def test_parser_recovers_parameter_names_and_types(tmp_path, elf64_with_dwarf):
    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(elf64_with_dwarf)

    info = parse_dwarf(sample)

    assert info.has_debug_info is True
    assert info.version == 4
    assert info.units == ("sample.c",)

    by_linkage = info.by_linkage_name()
    assert set(by_linkage) == {"add", "_ZN7MyClass7processEPKci"}

    add = by_linkage["add"]
    assert add.name == "add"
    assert add.return_type == "int"
    assert [(p.name, p.type_name) for p in add.parameters] == [
        ("a", "int"),
        ("b", "int"),
    ]
    assert add.decl_file == "/work/sample.c"
    assert add.decl_line == 3
    assert add.signature == "int add(int a, int b)"

    process = by_linkage["_ZN7MyClass7processEPKci"]
    assert process.name == "MyClass::process"
    assert [(p.name, p.type_name) for p in process.parameters] == [
        ("buffer", "char const*"),
        ("length", "unsigned int"),
    ]
    assert process.signature == (
        "int MyClass::process(char const* buffer, unsigned int length)"
    )
    assert process.decl_line == 7


def test_analyzer_reports_functions_with_locations(tmp_path, elf64_with_dwarf):
    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(elf64_with_dwarf)

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "basic.dwarf"
    data = result.data
    assert data["has_debug_info"] is True
    assert data["version"] == 4
    assert data["units"] == ["sample.c"]
    assert data["truncated"] is False

    records = {record["linkage_name"]: record for record in data["functions"]}
    assert records["add"]["parameters"] == [
        {"name": "a", "type": "int"},
        {"name": "b", "type": "int"},
    ]
    assert records["add"]["decl_file"] == "/work/sample.c"
    assert records["add"]["decl_line"] == 3
    assert records["add"]["low_pc"] == "0x1000"
    assert records["add"]["unit_name"] == "sample.c"


def test_analyzer_reports_missing_debug_information(tmp_path, elf64_with_symbols):
    """A library without debug sections reports that fact, not an error."""
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["has_debug_info"] is False
    assert result.data["functions"] == []
    assert "stripped" in result.data["note"]


def test_analyzer_fails_on_non_elf(tmp_path):
    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"not an elf file at all")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_analyzer_tolerates_truncated_debug_info(tmp_path, elf64_with_dwarf):
    """A cut-off .debug_info must not crash the run."""
    sample = tmp_path / "libcut.so"
    image = bytearray(elf64_with_dwarf)
    # Truncate the file mid-way through the debug sections.
    sample.write_bytes(bytes(image[: len(image) // 2]))

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["has_debug_info"] is False


def test_analyzer_respects_max_functions(tmp_path, elf64_with_dwarf):
    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(elf64_with_dwarf)
    options = {"capability_options": {"basic.dwarf": {"max_functions": 1}}}

    result = _analyze(sample, **options)

    assert result.data["truncated"] is True
    assert len(result.data["functions"]) == 1


def test_analyzer_ignores_unusable_max_functions(tmp_path, elf64_with_dwarf):
    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(elf64_with_dwarf)
    options = {"capability_options": {"basic.dwarf": {"max_functions": "bogus"}}}

    result = _analyze(sample, **options)

    assert result.data["truncated"] is False
    assert len(result.data["functions"]) == 2


def test_analyzer_result_is_json_serializable(tmp_path, elf64_with_dwarf):
    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(elf64_with_dwarf)

    payload = json.dumps(_analyze(sample).data)
    assert "process" in payload


def test_analyzer_is_registered_as_default_enabled():
    assert BasicDwarfAnalyzer.metadata.default_enabled is True


def test_dwarf_sections_are_readable_by_pyelftools(tmp_path, elf64_with_dwarf):
    """The synthetic debug information is valid DWARF, not just self-consistent."""
    pytest.importorskip("elftools", reason="pyelftools is a development dependency")
    from elftools.elf.elffile import ELFFile

    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(elf64_with_dwarf)
    with open(sample, "rb") as handle:
        elffile = ELFFile(handle)
        assert elffile.has_dwarf_info()
        dwarf = elffile.get_dwarf_info()
        subprograms = []
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    name = die.attributes.get("DW_AT_name")
                    subprograms.append(name.value.decode() if name else "?")
    assert sorted(subprograms) == ["add", "process"]
