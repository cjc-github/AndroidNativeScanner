"""Unit tests for the basic.jni analyzer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from jni_builder import (  # noqa: E402
    NAMED_FN_ADDR,
    ON_LOAD_ADDR,
    STRIPPED_FN_ADDR,
    build_jni_image,
    build_stripped_jni_image,
)

from soinsight.analyzers.jni import BasicJniAnalyzer  # noqa: E402
from soinsight.core.analyzer import AnalysisContext  # noqa: E402
from soinsight.core.models import (  # noqa: E402
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
)
from soinsight.infrastructure.config import RuntimeConfig  # noqa: E402


def _write(tmp_path, blob, name="libjni.so"):
    sample = tmp_path / name
    sample.write_bytes(blob)
    return sample


def _analyze(path, *, jni_count=0):
    target = AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=path.stat().st_size,
        sha256="test",
    )
    context = AnalysisContext("run", target, RuntimeConfig())
    context.add_result(
        AnalysisResult(
            analyzer_id="basic.symbols",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"jni_count": jni_count},
        )
    )
    return BasicJniAnalyzer().analyze(target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("basic").get_capability("jni")
    assert capability.id == BasicJniAnalyzer.metadata.id


def test_dynamic_registration_is_reported(tmp_path):
    sample = _write(
        tmp_path,
        build_jni_image(
            [("processData", "(Ljava/lang/String;)V", NAMED_FN_ADDR)],
            named_functions={NAMED_FN_ADDR: "native_process"},
        ),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["dynamic_count"] == 1
    assert result.data["on_load_present"] is True
    assert result.data["register_natives_imported"] is True
    entry = result.data["dynamic_registrations"][0]
    assert entry["method_name"] == "processData"
    assert entry["signature"] == "(Ljava/lang/String;)V"
    assert entry["function_symbol"] == "native_process"


def test_static_count_comes_from_basic_symbols(tmp_path):
    sample = _write(
        tmp_path,
        build_jni_image([("a", "()V", NAMED_FN_ADDR + 0x20)]),
    )

    result = _analyze(sample, jni_count=7)

    assert result.data["static_count"] == 7


def test_stripped_functions_are_flagged(tmp_path):
    sample = _write(
        tmp_path,
        build_stripped_jni_image(
            [("init", "()V", STRIPPED_FN_ADDR), ("run", "()V", STRIPPED_FN_ADDR + 0x20)]
        ),
    )

    result = _analyze(sample)

    assert result.data["dynamic_count"] == 2
    codes = [item.code for item in result.diagnostics]
    assert "JNI_STRIPPED_FUNCTIONS" in codes


def test_image_without_dynamic_registration_reports_info(tmp_path):
    sample = _write(
        tmp_path,
        build_jni_image(
            [("a", "()V", NAMED_FN_ADDR)],
            with_on_load=False,
            with_register_natives_import=False,
        ),
    )

    result = _analyze(sample)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["dynamic_count"] == 0
    codes = [item.code for item in result.diagnostics]
    assert "JNI_NO_DYNAMIC_REGISTRATION" in codes


def test_non_elf_target_fails(tmp_path):
    sample = tmp_path / "bad.so"
    sample.write_bytes(b"not an elf at all")

    result = _analyze(sample)

    assert result.status == AnalysisStatus.FAILED
    assert [item.code for item in result.diagnostics] == ["JNI_INVALID_ELF"]


def test_format_text_lists_the_registrations(tmp_path):
    sample = _write(
        tmp_path,
        build_jni_image(
            [("processData", "(Ljava/lang/String;)V", NAMED_FN_ADDR)],
            named_functions={NAMED_FN_ADDR: "native_process"},
        ),
    )

    result = _analyze(sample, jni_count=3)
    text = BasicJniAnalyzer().format_text(result)

    assert "JNI 注册" in text
    assert "processData" in text
    assert "(Ljava/lang/String;)V" in text
    assert "native_process" in text
    assert "FindClass" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    sample = tmp_path / "bad.so"
    sample.write_bytes(b"nope")
    result = _analyze(sample)
    result.status = AnalysisStatus.FAILED

    assert BasicJniAnalyzer().format_text(result) is None
