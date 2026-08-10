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
