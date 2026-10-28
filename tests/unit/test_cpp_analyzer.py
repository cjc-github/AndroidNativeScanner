"""Unit tests for the C++ recovery analyzer."""

import json

import pytest

from soinsight.analyzers.cpp import BasicCppAnalyzer
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


def _rtti_symbols() -> list[tuple]:
    """RTTI/vtable/special-member symbols for ``demo::Base``."""
    return [
        ("", 0, 3, 0xFFF1, 0, 0),                          # STT_SECTION
        ("_ZTV4Base", 1, 1, 6, 0x2000, 0x18),              # vtable
        ("_ZTI4Base", 1, 1, 6, 0x2100, 0x10),              # typeinfo
        ("_ZTS4Base", 1, 1, 6, 0x2200, 0x9),               # typeinfo name
        ("_ZN4BaseC1Ev", 1, 2, 6, 0x1000, 0x20),           # Base::Base()
        ("_ZN4BaseC2Ev", 1, 2, 6, 0x1000, 0x20),           # base-object clone
        ("_ZN4BaseD0Ev", 1, 2, 6, 0x1020, 0x20),           # deleting dtor
        ("_ZN4BaseD2Ev", 1, 2, 6, 0x1040, 0x20),           # base-object dtor
        ("_ZN4Base3fooEv", 1, 2, 6, 0x1080, 0x10),         # Base::foo()
        # Imported runtime machinery must not create class evidence.
        ("__class_type_info", 0, 2, 0, 0, 0),              # undefined import
        ("printf", 0, 2, 0, 0, 0),                         # undefined import
    ]


def _analyze(path, analyzers=None, **extra):
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    dwarf = BasicDwarfAnalyzer().analyze(target, context)
    context.add_result(dwarf)
    types = BasicTypesAnalyzer().analyze(target, context)
    context.add_result(types)
    return BasicCppAnalyzer().analyze(target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability("cpp")
    assert BasicCppAnalyzer.metadata.id == capability.id == "basic.cpp"
    assert BasicCppAnalyzer.metadata.requires == (
        "basic.elf",
        "basic.dwarf",
        "basic.types",
    )


def test_recovered_classes_come_from_rtti_symbols(tmp_path):
    sample = tmp_path / "librtti.so"
    sample.write_bytes(build_elf64_with_symbols(_rtti_symbols()))

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["class_count"] == 1
    record = data["classes"][0]
    assert record["name"] == "Base"
    assert record["sources"] == ["rtti", "symbols"]
    assert record["vtable"]["symbol"] == "_ZTV4Base"
    assert record["vtable"]["address"] == "0x2000"
    assert record["typeinfo"]["symbol"] == "_ZTI4Base"
    assert record["typeinfo_name"]["symbol"] == "_ZTS4Base"
    assert data["vtable_count"] == 1
    assert data["typeinfo_count"] == 1


def test_special_members_join_by_class_name(tmp_path):
    sample = tmp_path / "librtti.so"
    sample.write_bytes(build_elf64_with_symbols(_rtti_symbols()))

    result = _analyze(sample)
    record = result.data["classes"][0]

    clones = sorted(entry["clone"] for entry in record["constructors"])
    assert clones == ["C1", "C2"]
    dtors = sorted(entry["clone"] for entry in record["destructors"])
    assert dtors == ["D0", "D2"]
    for entry in record["constructors"] + record["destructors"]:
        assert entry["source"] == "symbols"
        assert entry["signature"].startswith("Base::")
    assert data_summary(result)["constructor_count"] == 2
    assert data_summary(result)["destructor_count"] == 2


def data_summary(result) -> dict:
    return result.data


def test_imported_symbols_never_create_class_evidence(tmp_path):
    symbols = _rtti_symbols() + [
        ("_ZTVN10__cxxabiv117__class_type_infoE", 0, 1, 0, 0, 0),
    ]
    sample = tmp_path / "librtti.so"
    sample.write_bytes(build_elf64_with_symbols(symbols))

    result = _analyze(sample)

    names = [record["name"] for record in result.data["classes"]]
    assert names == ["Base"]
    assert result.data["class_count"] == 1


def test_dwarf_classes_carry_inheritance_and_virtual_methods(tmp_path):
    symbols = [
        ("", 0, 3, 0xFFF1, 0, 0),
        ("_ZN4Base1fEv", 1, 2, 1, 0x1000, 0x20),
        ("g_count", 1, 1, 2, 0x2000, 4),
        ("printf", 0, 2, 0, 0, 0),
    ]
    sample = tmp_path / "libdwarf.so"
    sample.write_bytes(
        build_elf64_with_symbols(symbols, extra_sections=build_rich_dwarf_sections())
    )

    result = _analyze(sample)

    records = {record["name"]: record for record in result.data["classes"]}
    assert set(records) == {"Base", "Derived"}
    assert records["Base"]["sources"] == ["dwarf"]
    assert records["Base"]["byte_size"] == 8
    assert records["Derived"]["bases"] == [
        {
            "accessibility": None,
            "name": "Base",
            "offset": 0,
            "virtual": False,
        }
    ]
    methods = [entry["name"] for entry in records["Base"]["virtual_methods"]]
    assert methods == ["f"]
    assert records["Base"]["virtual_methods"][0]["linkage_name"] == "_ZN4Base1fEv"
    assert result.data["virtual_method_count"] == 1


def test_plain_c_image_reports_zero_classes(tmp_path):
    symbols = [
        ("", 0, 3, 0xFFF1, 0, 0),
        ("main", 1, 2, 6, 0x1000, 0x20),
        ("helper", 1, 2, 6, 0x1020, 0x10),
        ("printf", 0, 2, 0, 0, 0),
    ]
    sample = tmp_path / "libc.so"
    sample.write_bytes(build_elf64_with_symbols(symbols))

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["class_count"] == 0
    assert result.data["vtable_count"] == 0
    assert result.data["classes"] == []
    assert result.data["thunks"] == []
    assert result.data["construction_vtables"] == []


def test_invalid_elf_fails_with_invalid_elf_code(tmp_path):
    sample = tmp_path / "not-elf.so"
    sample.write_bytes(b"definitely not an ELF image")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_max_classes_option_truncates_with_diagnostic(tmp_path):
    symbols = [("", 0, 3, 0xFFF1, 0, 0)]
    for index in range(4):
        symbols.append((f"_ZTI5Type{index}", 1, 1, 6, 0x2000 + index, 0x10))
    sample = tmp_path / "libmany.so"
    sample.write_bytes(build_elf64_with_symbols(symbols))

    result = _analyze(sample, capability_options={"basic.cpp": {"max_classes": 2}})

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["class_count"] == 4
    assert len(result.data["classes"]) == 2
    assert result.data["truncated"] is True
    assert any(d.code == "CPP_TRUNCATED" for d in result.diagnostics)
    # Sub-counts cover the full class set, consistent with class_count.
    assert result.data["typeinfo_count"] == 4


def test_thunks_are_collected_as_flat_evidence(tmp_path):
    symbols = [("", 0, 3, 0xFFF1, 0, 0)]
    symbols.append(
        (
            "_ZThn16_N7Derived7forwardEv",
            1,
            2,
            6,
            0x3000,
            0x10,
        )
    )
    sample = tmp_path / "libthunk.so"
    sample.write_bytes(build_elf64_with_symbols(symbols))

    result = _analyze(sample)

    assert result.data["thunk_count"] == 1
    thunk = result.data["thunks"][0]
    assert thunk["symbol"] == "_ZThn16_N7Derived7forwardEv"
    assert thunk["kind"] == "virtual"


def test_result_payload_is_json_serializable(tmp_path):
    sample = tmp_path / "librtti.so"
    sample.write_bytes(build_elf64_with_symbols(_rtti_symbols()))

    result = _analyze(sample)

    payload = json.dumps(result.data)
    assert "Base" in payload


def test_format_text_renders_recovered_structure(tmp_path):
    sample = tmp_path / "librtti.so"
    sample.write_bytes(build_elf64_with_symbols(_rtti_symbols()))

    result = _analyze(sample)
    text = BasicCppAnalyzer().format_text(result)

    assert text is not None
    assert "=== C++ 恢复 ===" in text
    assert "类: 1" in text
    assert "vtable: 1" in text


def test_format_text_on_failure(tmp_path):
    from soinsight.core.models import AnalysisResult

    failed = AnalysisResult(analyzer_id="basic.cpp", analyzer_version="1.0.0",
                            status=AnalysisStatus.FAILED, data={})
    text = BasicCppAnalyzer().format_text(failed)

    assert text == "=== C++ 恢复失败 ==="
