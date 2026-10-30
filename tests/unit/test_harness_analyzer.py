"""Unit tests for automation.harness."""

import pytest

from soinsight.analyzers.harness import AutomationHarnessAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.harness import build_harness


def _candidate(**overrides):
    candidate = {
        "name": "parse",
        "linkage_name": "parse",
        "return_type": "int",
        "signature": "int parse(const unsigned char *buf, size_t len)",
        "kind": "parser",
        "score": 75,
        "parameters": [
            {"index": 0, "name": "buf", "type": "const unsigned char *", "role": "buffer"},
            {"index": 1, "name": "len", "type": "size_t", "role": "size"},
        ],
    }
    candidate.update(overrides)
    return candidate


def _analyze(candidates, **extra):
    target = AnalysisTarget(
        path=None, real_path=None, name="libsample.so", size=0, sha256="test"
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    context.add_result(
        AnalysisResult(
            analyzer_id="automation.fuzz-target",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"targets": list(candidates)},
        )
    )
    return AutomationHarnessAnalyzer().analyze(target, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("automation").get_capability(
        "harness"
    )
    assert capability.id == AutomationHarnessAnalyzer.metadata.id


def test_buffer_and_size_become_data_and_size():
    draft = build_harness(_candidate())

    assert "LLVMFuzzerTestOneInput" in draft.source
    assert "parse((const void *)data, size)" in draft.source
    assert "extern int parse(const unsigned char *buf, size_t len);" in draft.source
    assert draft.warnings == ()
    assert draft.template is True


def test_second_buffer_callback_and_out_pointer_are_warned():
    candidate = _candidate(
        signature="int parse(char *a, char *b, int (*cb)(void), char **out)",
        parameters=[
            {"index": 0, "name": "a", "type": "char *", "role": "buffer"},
            {"index": 1, "name": "b", "type": "char *", "role": "buffer"},
            {"index": 2, "name": "cb", "type": "int (*)(void)", "role": "callback"},
            {"index": 3, "name": "out", "type": "char **", "role": "out-pointer"},
        ],
    )

    draft = build_harness(candidate)

    assert "parse((const void *)data, NULL, NULL, NULL)" in draft.source
    joined = " ".join(draft.warnings)
    assert "第二个缓冲区" in joined
    assert "回调" in joined
    assert "输出指针" in joined


def test_entry_without_a_buffer_is_flagged():
    draft = build_harness(
        _candidate(
            parameters=[
                {"index": 0, "name": "mode", "type": "int", "role": "scalar"},
            ]
        )
    )

    assert "没有缓冲区参数" in " ".join(draft.warnings)


def test_cpp_signature_suppresses_the_prototype():
    draft = build_harness(
        _candidate(signature="int foo::parse(const unsigned char *, size_t)")
    )

    assert "extern int foo::parse" not in draft.source
    assert "不是纯 C 形式" in " ".join(draft.warnings)


def test_unknown_engine_is_rejected():
    with pytest.raises(ValueError):
        build_harness(_candidate(), engine="afl")


def test_analyzer_picks_the_top_candidate_by_default():
    result = _analyze([_candidate()])

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["generated"] is True
    assert result.data["target_name"] == "parse"
    assert "parse((const void *)data, size)" in result.data["harness"]["source"]


def test_analyzer_honours_the_requested_target_name():
    result = _analyze(
        [_candidate(), _candidate(name="other", linkage_name="other")],
        capability_options={"automation.harness": {"target_name": "other"}},
    )

    assert result.data["target_name"] == "other"


def test_analyzer_reports_a_missing_target():
    result = _analyze(
        [_candidate()],
        capability_options={"automation.harness": {"target_name": "nope"}},
    )

    assert result.data["generated"] is False
    assert [d.code for d in result.diagnostics] == ["HARNESS_NO_TARGET"]


def test_analyzer_warns_when_the_template_is_incomplete():
    candidate = _candidate(
        parameters=[
            {"index": 0, "name": "buf", "type": "char *", "role": "buffer"},
            {"index": 1, "name": "cb", "type": "int (*)(void)", "role": "callback"},
        ]
    )

    result = _analyze([candidate])

    codes = [d.code for d in result.diagnostics]
    assert "HARNESS_TEMPLATE_INCOMPLETE" in codes


def test_format_text_includes_the_source():
    result = _analyze([_candidate()])
    text = AutomationHarnessAnalyzer().format_text(result)

    assert "Harness 生成" in text
    assert "--- harness.c ---" in text
    assert "LLVMFuzzerTestOneInput" in text


def test_format_text_is_none_for_a_failed_result():
    result = _analyze([_candidate()])
    result.status = AnalysisStatus.FAILED

    assert AutomationHarnessAnalyzer().format_text(result) is None


def test_fed_buffer_without_a_length_parameter_is_warned():
    """A buffer with no detected length leaves a literal 0 and must say so."""
    candidate = _candidate(
        name="process",
        linkage_name="process",
        return_type="int",
        signature="int process(const unsigned char *buf, int mode)",
        parameters=[
            {"index": 0, "name": "buf", "type": "const unsigned char *", "role": "buffer"},
            {"index": 1, "name": "mode", "type": "int", "role": "scalar"},
        ],
    )

    draft = build_harness(candidate)

    assert "process((const void *)data, 0)" in draft.source
    assert "没有识别到长度参数" in " ".join(draft.warnings)


def test_recognised_length_parameter_produces_no_such_warning():
    draft = build_harness(_candidate())

    assert "没有识别到长度参数" not in " ".join(draft.warnings)
    assert "parse((const void *)data, size)" in draft.source


def test_signature_carrying_the_return_type_needs_no_metadata():
    """``int parse(...)`` already names the return type: emit it as is."""
    draft = build_harness(_candidate(return_type=None))

    assert "extern int parse(const unsigned char *buf, size_t len);" in draft.source
    assert draft.warnings == ()


def test_bare_signature_uses_the_return_type_metadata():
    draft = build_harness(
        _candidate(return_type="size_t", signature="parse(const unsigned char *buf, size_t len)")
    )

    assert "extern size_t parse(const unsigned char *buf, size_t len);" in draft.source
    assert draft.warnings == ()


def test_bare_signature_without_metadata_states_the_int_assumption():
    draft = build_harness(
        _candidate(return_type=None, signature="parse(const unsigned char *buf, size_t len)")
    )

    assert "extern int parse(const unsigned char *buf, size_t len);" in draft.source
    assert "按 int 假设" in " ".join(draft.warnings)
