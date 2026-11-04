"""Unit tests for Markdown and HTML report renderers."""

from soinsight.application import ApplicationResponse
from soinsight.core.models import AnalysisStatus, AnalysisTarget, ScanResult
from soinsight.renderers import create_default_renderer_registry


def _response(tmp_path):
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    return ApplicationResponse(result=ScanResult(target=target, status=AnalysisStatus.SUCCESS))


def test_markdown_renderer_outputs_heading(tmp_path):
    renderer = create_default_renderer_registry().get("markdown")

    text = renderer.render(_response(tmp_path))

    assert text.startswith("# SOInsight Analysis Report\n")
    assert "## Target" in text


def test_html_renderer_outputs_document(tmp_path):
    renderer = create_default_renderer_registry().get("html")

    text = renderer.render(_response(tmp_path))

    assert text.startswith("<!doctype html>")
    assert "<title>SOInsight Analysis Report</title>" in text


def _jni_response(tmp_path, **overrides):
    """A response whose result carries a basic.jni section."""
    from soinsight.core.models import AnalysisResult

    data = {
        "static_count": 1,
        "dynamic_count": 1,
        "dynamic_array_count": 1,
        "on_load_present": True,
        "register_natives_imported": True,
        "dynamic_registrations": [
            {
                "method_name": "send",
                "qualified": False,
                "signature": "(Ljava/lang/String;)V",
                "function_address": "0xca2d",
                "function_symbol": "native_send",
                "function_named": True,
                "array_slot": "0x2d098",
                "relocation_offsets": ["0x2d098", "0x2d09c", "0x2d0a0"],
            }
        ],
    }
    data.update(overrides)
    response = _response(tmp_path)
    result = response.result
    result.results["basic.jni"] = AnalysisResult(
        analyzer_id="basic.jni",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data=data,
    )
    return response


def test_html_renderer_shows_the_dynamic_registration_table(tmp_path):
    renderer = create_default_renderer_registry().get("html")

    text = renderer.render(_jni_response(tmp_path))

    assert "<h2>JNI registrations</h2>" in text
    assert "<code>send</code>" in text
    assert "(Ljava/lang/String;)V" in text
    assert "native_send" in text
    # The address locates the function in a disassembly, so it is shown even
    # when a symbol name is available.
    assert "0xca2d" in text
    # A bare method name cannot reveal the Java class, and the report says so.
    assert "FindClass" in text


def test_html_renderer_marks_a_stripped_function(tmp_path):
    renderer = create_default_renderer_registry().get("html")

    text = renderer.render(
        _jni_response(
            tmp_path,
            dynamic_registrations=[
                {
                    "method_name": "init",
                    "qualified": False,
                    "signature": "()V",
                    "function_address": "0x1040",
                    "function_symbol": None,
                    "function_named": False,
                    "array_slot": "0x2d098",
                    "relocation_offsets": [],
                }
            ],
        )
    )

    assert "no symbol name" in text
    assert "0x1040" in text


def test_html_renderer_explains_a_missing_array(tmp_path):
    renderer = create_default_renderer_registry().get("html")

    text = renderer.render(
        _jni_response(
            tmp_path, dynamic_count=0, dynamic_array_count=0, dynamic_registrations=[]
        )
    )

    assert "no array shaped like" in text


def test_html_renderer_says_when_there_is_no_dynamic_registration(tmp_path):
    renderer = create_default_renderer_registry().get("html")

    text = renderer.render(
        _jni_response(
            tmp_path,
            static_count=2,
            dynamic_count=0,
            dynamic_array_count=0,
            on_load_present=False,
            register_natives_imported=False,
            dynamic_registrations=[],
        )
    )

    assert "does not register natives dynamically" in text


def test_html_renderer_shows_every_collected_analyzer(tmp_path):
    """The report is the only output the packaged web console shows.

    An analyzer without a section would simply be missing from it, so the
    generic fallback lists whatever has no dedicated section.
    """
    from soinsight.core.models import AnalysisResult

    response = _response(tmp_path)
    result = response.result
    result.results["advanced.strings"] = AnalysisResult(
        analyzer_id="advanced.strings",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={"classified": {"url": {"count": 2, "hits": ["a", "b"]}}},
    )

    text = create_default_renderer_registry().get("html").render(response)

    assert "advanced.strings" in text
    assert "url" in text
    assert "2" in text
