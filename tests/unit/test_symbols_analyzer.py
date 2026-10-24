"""Unit tests for the built-in symbol analyzer."""

import json
from pathlib import Path

import pytest

from soinsight.analyzers.symbols import BasicSymbolsAnalyzer
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


def _analyze(path: Path, **extra) -> object:
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return BasicSymbolsAnalyzer().analyze(target, context)


def test_analyzer_id_is_namespaced_and_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability("symbols")
    assert BasicSymbolsAnalyzer.metadata.id == capability.id == "basic.symbols"


def test_analyzer_declares_elf_dependency():
    assert BasicSymbolsAnalyzer.metadata.requires == ("basic.elf",)


def test_analyzer_collects_exported_functions_with_signatures(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "basic.symbols"
    assert result.data["symbol_tables"] == [".dynsym", ".symtab"]
    assert result.data["stripped"] is False
    assert result.data["counts"] == {
        "exported_functions": 5,
        "exported_data": 1,
        "exported_unclassified": 0,
        "imports": 1,
        "local": 2,  # the STT_SECTION marker appears in both tables
    }
    assert result.data["unclassified_symbols"] == []
    assert result.data["demangled_count"] == 3
    assert result.data["jni_count"] == 2

    signatures = [record["signature"] for record in result.data["functions"]]
    assert signatures == [
        "com.example.Foo.nativeInit",
        "com.example.Foo.nativeInit(int, java.lang.String)",
        "foo::bar(int)",
        "std::vector<int, std::allocator<int> >::push_back(int const&)",
        "android::IBinder::~IBinder()",
    ]


def test_analyzer_reports_symbol_facts_and_classification(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)

    result = _analyze(sample)
    jni = result.data["functions"][1]

    assert jni["language"] == "jni"
    assert jni["kind"] == "function"
    assert jni["parameters"] == ["int", "java.lang.String"]
    assert jni["jni"] == {
        "package": "com.example",
        "class": "Foo",
        "method": "nativeInit",
        "parameters": ["int", "java.lang.String"],
        "return_type": None,
    }
    assert jni["bind"] == "GLOBAL"
    assert jni["visibility"] == "DEFAULT"
    assert jni["address"] == "0x1040"
    assert jni["size"] == 48
    assert jni["source"] == ".dynsym"

    cpp = result.data["functions"][3]
    assert cpp["language"] == "c++"
    assert cpp["kind"] == "method"
    assert cpp["namespace"] == "std::vector<int, std::allocator<int> >"
    assert cpp["short_name"] == "push_back"
    assert cpp["demangled"]["qualified_name"] == (
        "std::vector<int, std::allocator<int> >::push_back"
    )


def test_analyzer_deduplicates_symbols_shared_by_both_tables(tmp_path, elf64_with_symbols):
    """The same export appears in .dynsym and .symtab; .dynsym wins."""
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)

    result = _analyze(sample)

    names = [record["name"] for record in result.data["functions"]]
    assert len(names) == len(set(names))
    assert all(record["source"] == ".dynsym" for record in result.data["functions"])


def test_analyzer_handles_stripped_image(tmp_path, elf64_stripped_symbols):
    sample = tmp_path / "libstripped.so"
    sample.write_bytes(elf64_stripped_symbols)

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["symbol_tables"] == [".dynsym"]
    assert result.data["stripped"] is True
    assert result.data["counts"]["exported_functions"] == 5


def test_analyzer_optionally_includes_data_and_imports(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)
    options = {
        "capability_options": {
            "basic.symbols": {"include_data_symbols": True, "include_imports": True}
        }
    }

    result = _analyze(sample, **options)

    assert [record["name"] for record in result.data["data_symbols"]] == ["g_counter"]
    assert [record["name"] for record in result.data["imports"]] == ["printf"]


def test_analyzer_options_can_disable_demangling_and_jni(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)
    options = {"capability_options": {"basic.symbols": {"demangle": False, "jni_decode": False}}}

    result = _analyze(sample, **options)

    assert result.data["demangled_count"] == 0
    assert result.data["jni_count"] == 0
    assert all(record["demangled"] is None for record in result.data["functions"])
    assert all(record["jni"] is None for record in result.data["functions"])
    assert [record["signature"] for record in result.data["functions"]] == [
        "Java_com_example_Foo_nativeInit",
        "Java_com_example_Foo_nativeInit__ILjava_lang_String_2",
        "_ZN3foo3barEi",
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "_ZN7android7IBinderD2Ev",
    ]


def test_analyzer_truncates_large_export_lists(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)
    options = {"capability_options": {"basic.symbols": {"max_functions": 2}}}

    result = _analyze(sample, **options)

    assert len(result.data["functions"]) == 2
    assert result.data["counts"]["exported_functions"] == 2
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "SYMBOLS_TRUNCATED" in codes


def test_analyzer_rejects_out_of_range_option_values(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)
    options = {"capability_options": {"basic.symbols": {"max_functions": 10 ** 9}}}

    result = _analyze(sample, **options)

    # Values are clamped, not trusted.
    assert result.status == AnalysisStatus.SUCCESS
    assert len(result.data["functions"]) == 5


def test_analyzer_warns_when_no_symbol_table_is_present(tmp_path, minimal_elf64_little):
    sample = tmp_path / "headeronly.so"
    sample.write_bytes(minimal_elf64_little)

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["counts"]["exported_functions"] == 0
    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert "NO_SYMBOL_TABLE" in codes


def test_analyzer_fails_on_non_elf(tmp_path):
    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"not an elf file at all")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_analyzer_result_is_json_serializable(tmp_path, elf64_with_symbols):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(elf64_with_symbols)

    result = _analyze(sample)

    payload = json.dumps(
        {
            "analyzer_id": result.analyzer_id,
            "status": result.status.value,
            "data": result.data,
        }
    )
    assert "push_back" in payload


def test_analyzer_is_registered_as_default_enabled():
    assert BasicSymbolsAnalyzer.metadata.default_enabled is True
    assert BasicSymbolsAnalyzer.metadata.cacheable is True


def test_analyzer_covers_every_export_table_entry(tmp_path):
    """Every defined global/weak symbol lands in exactly one bucket.

    Exercises the cases a normal library corpus does not: an untyped export
    (assembly without ".type"), STT_GNU_IFUNC, a weak function, an absolute
    and a common symbol, and an import.
    """
    from tests.conftest import build_elf64_with_symbols

    STB_GLOBAL, STB_WEAK, STB_LOCAL = 1, 2, 0
    STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_GNU_IFUNC = 0, 1, 2, 10
    SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2
    symbols = [
        ("", STB_LOCAL, 3, SHN_UNDEF, 0, 0),
        ("plain_func", STB_GLOBAL, STT_FUNC, 1, 0x1000, 0x40),
        ("untyped_export", STB_GLOBAL, STT_NOTYPE, 1, 0x1040, 0x20),
        ("weak_func", STB_WEAK, STT_FUNC, 1, 0x1080, 0x18),
        ("ifunc", STB_GLOBAL, STT_GNU_IFUNC, 1, 0x10A0, 0x10),
        ("abs_func", STB_GLOBAL, STT_FUNC, SHN_ABS, 0x2000, 0x8),
        ("common_obj", STB_GLOBAL, STT_OBJECT, SHN_COMMON, 0, 0x10),
        ("imported", STB_GLOBAL, STT_NOTYPE, SHN_UNDEF, 0, 0),
    ]
    sample = tmp_path / "edge.so"
    sample.write_bytes(build_elf64_with_symbols(symbols, with_symtab=False))
    options = {
        "capability_options": {
            "basic.symbols": {"include_data_symbols": True, "include_imports": True}
        }
    }

    result = _analyze(sample, **options)

    assert result.data["counts"] == {
        "exported_functions": 4,       # plain, weak, ifunc, abs
        "exported_data": 1,            # common
        "exported_unclassified": 1,    # untyped
        "imports": 1,
        "local": 0,
    }
    # Nothing from the export table is silently dropped.
    assert [record["name"] for record in result.data["functions"]] == [
        "plain_func", "weak_func", "ifunc", "abs_func",
    ]
    assert [record["name"] for record in result.data["unclassified_symbols"]] == [
        "untyped_export",
    ]
    assert [record["name"] for record in result.data["data_symbols"]] == ["common_obj"]
    assert [record["name"] for record in result.data["imports"]] == ["imported"]


def test_analyzer_reports_untyped_exports_even_without_options(tmp_path):
    """Untyped exports are always surfaced, unlike data and imports."""
    from tests.conftest import build_elf64_with_symbols

    symbols = [
        ("", 0, 3, 0xFFF1, 0, 0),
        ("untyped_export", 1, 0, 1, 0x1000, 0x20),
        ("real_func", 1, 2, 1, 0x1040, 0x40),
    ]
    sample = tmp_path / "untyped.so"
    sample.write_bytes(build_elf64_with_symbols(symbols, with_symtab=False))

    result = _analyze(sample)

    assert result.data["counts"]["exported_functions"] == 1
    assert result.data["counts"]["exported_unclassified"] == 1
    assert "data_symbols" not in result.data
    assert "imports" not in result.data
