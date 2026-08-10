"""Unit tests for the SARIF report renderer."""

import json

from soinsight.application import ApplicationResponse
from soinsight.core.models import AnalysisStatus, AnalysisTarget, ScanResult
from soinsight.renderers import create_default_renderer_registry


def test_sarif_renderer_outputs_sarif_document(tmp_path):
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    response = ApplicationResponse(result=ScanResult(target=target, status=AnalysisStatus.SUCCESS))

    text = create_default_renderer_registry().get("sarif").render(response)
    payload = json.loads(text)

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "SOInsight"
    assert payload["runs"][0]["results"] == []
