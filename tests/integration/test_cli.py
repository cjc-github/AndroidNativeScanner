from dataclasses import dataclass
from io import StringIO
import json

from soinsight.cli.main import main
from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus


@dataclass
class FrameworkAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="file",
        name="Framework Test Analyzer",
        version="1.0.0",
    )

    def analyze(self, target, context):
        return AnalysisResult(
            analyzer_id="file",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"size": target.size},
        )


def test_cli_runs_registered_analyzer_and_emits_json(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"ELF-test")
    registry = AnalyzerRegistry()
    registry.register(FrameworkAnalyzer())
    stdout = StringIO()

    exit_code = main(
        ["file", str(target), "--format", "json"],
        registry=registry,
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["status"] == "success"
    assert payload["result"]["results"]["file"]["data"]["size"] == 8


def test_cli_reports_unregistered_analyzer(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["elf", str(target)], stdout=stdout)

    assert exit_code == 3
    assert "ANALYSIS_PLAN_ERROR" in stdout.getvalue()


def test_cli_resolves_analyzers_from_profile(tmp_path):
    from soinsight.core.profiles import ProfileRegistry, ScanProfile

    target = tmp_path / "sample.so"
    target.write_bytes(b"profile")
    registry = AnalyzerRegistry()
    registry.register(FrameworkAnalyzer())
    profiles = ProfileRegistry()
    profiles.register(ScanProfile("quick", "Quick", ("file",)))
    stdout = StringIO()

    exit_code = main(
        ["scan", str(target), "--profile", "quick", "--format", "json"],
        registry=registry,
        profiles=profiles,
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["profile"] == "quick"
    assert payload["result"]["resolved_analyzers"] == ["file"]
