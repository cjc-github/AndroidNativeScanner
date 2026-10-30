"""Unit tests for automation.fuzz-target."""

from pathlib import Path

from soinsight.analyzers.fuzz_target import AutomationFuzzTargetAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig
from soinsight.infrastructure.fuzz_targets import rank_candidates


def _target() -> AnalysisTarget:
    """A synthetic target descriptor; nothing on disk is read by this analyzer."""
    return AnalysisTarget(
        path=Path("libsample.so"),
        real_path=Path("libsample.so"),
        name="libsample.so",
        size=0,
        sha256="test",
    )


def _function(
    name: str,
    *,
    parameters=None,
    kind: str = "function",
    bind: str = "STB_GLOBAL",
    language: str = "c",
    jni=None,
    signature=None,
    short_name=None,
):
    return {
        "name": name,
        "signature": signature or name,
        "short_name": short_name or name,
        "kind": kind,
        "bind": bind,
        "language": language,
        "parameters": parameters or [],
        "jni": jni,
    }


def _analyze(functions, signatures=(), **extra):
    context = AnalysisContext("run", _target(), RuntimeConfig(extra=extra))
    for analyzer_id, data in (
        ("basic.symbols", {"functions": list(functions)}),
        ("basic.types", {"signatures": list(signatures)}),
    ):
        context.add_result(
            AnalysisResult(
                analyzer_id=analyzer_id,
                analyzer_version="1.0.0",
                status=AnalysisStatus.SUCCESS,
                data=data,
            )
        )
    return AutomationFuzzTargetAnalyzer().analyze(None, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("automation").get_capability(
        "fuzz-target"
    )
    assert capability.id == AutomationFuzzTargetAnalyzer.metadata.id


def test_buffer_and_length_pair_scores_highest():
    report = rank_candidates(
        (
            _function(
                "parse_header",
                parameters=[
                    {"name": "data", "type": "unsigned char *"},
                    {"name": "len", "type": "size_t"},
                ],
            ),
            _function("get_version"),
        ),
        (),
    )

    by_name = {item.name: item for item in report.candidates}
    assert by_name["parse_header"].score > by_name["get_version"].score
    assert by_name["parse_header"].buffer_length_pairs == 1
    assert by_name["parse_header"].kind == "parser"
    roles = [item.role for item in by_name["parse_header"].parameters]
    assert roles == ["buffer", "size"]


def test_jni_export_is_marked_and_ranked_first():
    report = rank_candidates(
        (
            _function(
                "Java_com_example_Foo_nativeParse",
                parameters=[
                    {"name": "env", "type": "JNIEnv *"},
                    {"name": "input", "type": "jbyteArray"},
                ],
                language="jni",
                jni={
                    "package": "com.example",
                    "class": "Foo",
                    "method": "nativeParse",
                    "parameters": ["[B"],
                    "return_type": "I",
                },
                short_name="nativeParse",
            ),
            _function("plain_export"),
        ),
        (),
    )

    first = report.candidates[0]
    assert first.kind == "jni"
    assert first.name == "nativeParse"
    assert "JNI 导出" in " ".join(first.reasons)


def test_dwarf_signatures_override_symbol_parameters():
    report = rank_candidates(
        (
            _function("parse", parameters=[]),
        ),
        (
            {
                "name": "parse",
                "linkage_name": "parse",
                "parameters": [
                    {"name": "buf", "type": "const char *"},
                    {"name": "size", "type": "unsigned int"},
                ],
            },
        ),
    )

    candidate = report.candidates[0]
    assert [item.type for item in candidate.parameters] == [
        "const char *",
        "unsigned int",
    ]
    assert "不" not in " ".join(candidate.reasons)


def test_local_symbols_are_not_candidates():
    report = rank_candidates(
        (_function("hidden_parse", bind="STB_LOCAL"),),
        (),
    )

    assert report.candidates == ()


def test_out_pointer_and_callback_are_classified():
    report = rank_candidates(
        (
            _function(
                "decode_message",
                parameters=[
                    {"name": "out", "type": "char **"},
                    {"name": "cb", "type": "int (*)(void *)"},
                    {"name": "mode", "type": "int"},
                ],
            ),
        ),
        (),
    )

    roles = [item.role for item in report.candidates[0].parameters]
    assert roles == ["out-pointer", "callback", "scalar"]


def test_analyzer_reports_counts_and_marks_the_ranking_heuristic():
    result = _analyze(
        [
            _function(
                "parse",
                parameters=[
                    {"name": "buf", "type": "char *"},
                    {"name": "len", "type": "size_t"},
                ],
            ),
            _function("get_version"),
        ]
    )

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data["heuristic"] is True
    assert result.data["target_count"] == 2
    assert result.data["parser_like_count"] == 1
    assert result.data["buffer_length_pair_count"] == 1


def test_min_score_filters_and_max_targets_truncates():
    functions = tuple(_function(f"parse_{index}") for index in range(5))
    filtered = _analyze(functions, capability_options={
        "automation.fuzz-target": {"max_targets": 2}
    })
    strict = _analyze(functions, capability_options={
        "automation.fuzz-target": {"min_score": 90}
    })

    assert filtered.data["target_count"] == 2
    assert strict.data["target_count"] == 0


def test_no_exported_functions_warns():
    result = _analyze([])

    assert result.data["target_count"] == 0
    assert [d.code for d in result.diagnostics] == ["FUZZ_NO_ENTRYPOINTS"]


def test_format_text_reports_candidates():
    result = _analyze(
        [
            _function(
                "parse",
                parameters=[
                    {"name": "buf", "type": "char *"},
                    {"name": "len", "type": "size_t"},
                ],
            )
        ]
    )
    text = AutomationFuzzTargetAnalyzer().format_text(result)

    assert "Fuzz 目标识别" in text
    assert "parse" in text
    assert "启发式" in text


def test_format_text_is_none_for_a_failed_result():
    result = _analyze([])
    result.status = AnalysisStatus.FAILED

    assert AutomationFuzzTargetAnalyzer().format_text(result) is None
