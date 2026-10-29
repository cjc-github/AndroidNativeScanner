"""Unit tests for the ``basic.dynamic`` analyzer and its ELF facts.

The fixtures are hand-built ELF64 images: a shared object with a
``.dynamic`` table, a dynamic string table, a dynamic symbol table and a
``.rela.dyn`` relocation table.  Building them by hand keeps the expected
values obvious -- every offset in the test is a literal, not something the
builder happened to produce.
"""

from soinsight.analyzers.dynamic_link import BasicDynamicAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.elf import parse_bytes

from elf_builder import (
    DT_FLAGS,
    DT_NEEDED,
    DT_NULL,
    DT_RUNPATH,
    DT_RPATH,
    DT_SONAME,
    DT_STRTAB,
    DT_SYMTAB,
    DT_TEXTREL,
    PF_R,
    PF_W,
    PF_X,
    PT_GNU_RELRO,
    PT_LOAD,
    SHT_DYNAMIC,
    SHT_DYNSYM,
    SHT_PROGBITS,
    SHT_RELA,
    SHT_STRTAB,
    build_elf as _build_elf,
    dynamic_image as _dynamic_image,
    make_dynstr as _dynstr,
    make_dynsym as _dynsym,
)

def _target(path):
    data = path.read_bytes()
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=len(data),
        sha256="test-sha256",
    )


def _analyze(path, **extra):
    target = _target(path)
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    return BasicDynamicAnalyzer().analyze(target, context)


def _write(tmp_path, blob, name="libsample.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability(
        "dynamic"
    )
    assert BasicDynamicAnalyzer.metadata.id == capability.id == "basic.dynamic"


def test_analyzer_reports_needed_libraries_and_soname(tmp_path):
    sample = _write(
        tmp_path,
        _dynamic_image(needed=("libc.so", "libm.so"), soname="libsample.so"),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["has_dynamic"] is True
    assert result.data["needed"] == ["libc.so", "libm.so"]
    assert result.data["needed_count"] == 2
    assert result.data["soname"] == "libsample.so"


def test_analyzer_reports_search_path_entries(tmp_path):
    sample = _write(
        tmp_path,
        _dynamic_image(runpath="/opt/lib:/usr/lib"),
    )

    result = _analyze(sample)

    assert result.data["runpath"] == "/opt/lib:/usr/lib"
    assert result.data["rpath"] is None
    assert result.data["search_path"] == ["/opt/lib", "/usr/lib"]


def test_analyzer_reports_relocations_with_symbol_names(tmp_path):
    sample = _write(
        tmp_path,
        _dynamic_image(
            needed=("libc.so",),
            dynsym_names=[("memcpy", 0, 0), ("free", 0, 0)],
            rela_entries=((0x4000, 1, 7), (0x4008, 2, 6), (0x4010, 0, 8)),
        ),
    )

    result = _analyze(sample)

    relocations = result.data["relocations"]
    assert relocations["total"] == 3
    assert relocations["by_section"] == {".rela.dyn": 3}
    assert relocations["import_count"] == 2
    assert relocations["entries"][0]["symbol"] == "memcpy"
    assert relocations["entries"][0]["type"] == "JUMP_SLOT"
    assert relocations["entries"][2]["symbol"] is None
    assert relocations["entries"][2]["type"] == "RELATIVE"


def test_analyzer_reports_constructors(tmp_path):
    sample = _write(
        tmp_path,
        _dynamic_image(init_array=(0x5000, 16)),
    )

    result = _analyze(sample)

    assert result.data["init_array"] == ["0x1234", "0x1234"]
    assert result.data["constructor_count"] == 2


def test_analyzer_reports_bind_now_and_textrel_flags(tmp_path):
    sample = _write(
        tmp_path,
        _dynamic_image(flags=0x8, textrel=True),
    )

    result = _analyze(sample)

    flags = result.data["flags"]
    assert flags["bind_now"] is True
    assert flags["textrel"] is True


def test_analyzer_truncates_the_relocation_list(tmp_path):
    sample = _write(
        tmp_path,
        _dynamic_image(
            dynsym_names=[("memcpy", 0, 0)],
            rela_entries=((0x4000, 1, 7), (0x4008, 1, 7), (0x4010, 1, 7)),
        ),
    )

    result = _analyze(
        sample, capability_options={"basic.dynamic": {"max_relocations": 1}}
    )

    relocations = result.data["relocations"]
    assert relocations["total"] == 3
    assert len(relocations["entries"]) == 1
    assert relocations["truncated"] is True
    codes = {item.code for item in result.diagnostics}
    assert "RELOCATIONS_TRUNCATED" in codes


def test_analyzer_warns_when_the_image_has_no_dynamic_section(tmp_path):
    sample = _write(
        tmp_path,
        _build_elf(
            [
                {
                    "name": ".text",
                    "type": SHT_PROGBITS,
                    "flags": PF_R | PF_X,
                    "addr": 0x1000,
                    "data": b"\x90" * 16,
                }
            ]
        ),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["has_dynamic"] is False
    codes = {item.code for item in result.diagnostics}
    assert "NO_DYNAMIC_SECTION" in codes


def test_analyzer_rejects_non_elf(tmp_path):
    sample = _write(tmp_path, b"not an elf file at all", name="plain.txt")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "INVALID_ELF"


def test_format_text_summarizes_the_dynamic_facts(tmp_path):
    sample = _write(tmp_path, _dynamic_image(needed=("libc.so",)))

    result = _analyze(sample)
    text = BasicDynamicAnalyzer().format_text(result)

    assert text.startswith("=== 动态链接信息 ===")
    assert "libc.so" in text
    assert "重定位: " in text
