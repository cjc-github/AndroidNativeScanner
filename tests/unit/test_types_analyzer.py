"""Unit tests for the recovered-type analyzer."""

import json

import pytest

from soinsight.analyzers.dwarf import BasicDwarfAnalyzer
from soinsight.analyzers.types import BasicTypesAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig

from conftest import build_elf64_with_symbols, build_rich_dwarf_sections


def _target(path) -> AnalysisTarget:
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test-sha256",
    )


def _types_elf() -> bytes:
    """An ELF carrying a symbol table plus rich debug information."""
    symbols = [
        ("", 0, 3, 0xFFF1, 0, 0),                      # STT_SECTION
        ("_ZN4Base1fEv", 1, 2, 1, 0x1000, 0x20),       # Base::f() method
        ("_ZN7DerivedC1Ev", 1, 2, 1, 0x1020, 0x30),    # Derived::Derived()
        ("g_count", 1, 1, 2, 0x2000, 4),               # exported data object
        ("printf", 1, 0, 0, 0, 0),                     # import
    ]
    return build_elf64_with_symbols(symbols, extra_sections=build_rich_dwarf_sections())


def _analyze(path, **extra):
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    dwarf = BasicDwarfAnalyzer().analyze(target, context)
    context.add_result(dwarf)
    return BasicTypesAnalyzer().analyze(target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability("types")
    assert BasicTypesAnalyzer.metadata.id == capability.id == "basic.types"
    assert BasicTypesAnalyzer.metadata.requires == ("basic.elf", "basic.dwarf")


def test_analyzer_recovers_composite_types_and_variables(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libtypes.so"
    sample.write_bytes(elf64_with_symbols)

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "basic.types"
    assert result.data["has_debug_info"] is False
    assert result.data["type_count"] == 0
    assert result.data["variable_count"] == 1  # g_counter from the symbol table
    assert result.data["function_count"] == 3  # C++ symbols merged from ELF
    names = [record["name"] for record in result.data["signatures"]]
    assert "foo::bar(int)" in names
    assert "std::vector<int, std::allocator<int> >::push_back(int const&)" in names
    assert "android::IBinder::~IBinder()" in names


def test_analyzer_recovers_rich_types_from_dwarf(tmp_path):
    sample = tmp_path / "librich.so"
    sample.write_bytes(_types_elf())

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["has_debug_info"] is True
    assert data["type_count"] == 3

    by_name = {record["name"]: record for record in data["types"]}
    derived = by_name["Derived"]
    assert derived["kind"] == "class"
    assert derived["byte_size"] == 16
    assert [base["name"] for base in derived["bases"]] == ["Base"]
    assert derived["bases"][0]["offset"] == 0
    assert [member["name"] for member in derived["members"]] == ["x"]
    assert derived["members"][0]["offset"] == 8

    color = by_name["Color"]
    assert color["kind"] == "enum"
    assert [(e["name"], e["value"]) for e in color["enumerators"]] == [
        ("RED", 0),
        ("GREEN", 1),
    ]

    variables = {record["name"]: record for record in data["variables"]}
    assert variables["g_count"]["type_name"] == "int"

    signatures = {record.get("linkage_name") or record["name"]: record
                  for record in data["signatures"]}
    assert signatures["_ZN4Base1fEv"]["source"] == "dwarf"

    # JSON serializable end-to-end.
    json.dumps(data)


def test_analyzer_merges_symbol_and_dwarf_signatures(tmp_path):
    sample = tmp_path / "libmerge.so"
    sample.write_bytes(_types_elf())

    result = _analyze(sample)

    by_linkage = {record.get("linkage_name"): record for record in result.data["signatures"]}
    assert by_linkage["_ZN4Base1fEv"]["source"] == "dwarf"
    # Symbol table records that DWARF did not describe are still surfaced.
    assert by_linkage["_ZN7DerivedC1Ev"]["source"] == "symbols"


def test_analyzer_is_json_serializable(tmp_path):
    sample = tmp_path / "libtypes.so"
    sample.write_bytes(_types_elf())

    result = _analyze(sample)

    encoded = json.dumps(result.data)
    assert isinstance(encoded, str)
