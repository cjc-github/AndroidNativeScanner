from dataclasses import dataclass
from io import StringIO
import json

from soinsight.cli.main import main
from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus


@dataclass
class FrameworkAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="basic.file",
        name="Framework Test Analyzer",
        version="1.0.0",
    )

    def analyze(self, target, context):
        return AnalysisResult(
            analyzer_id="basic.file",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"size": target.size, "config": context.config.extra},
        )


def test_cli_runs_registered_analyzer_and_emits_json(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"ELF-test")
    registry = AnalyzerRegistry()
    registry.register(FrameworkAnalyzer())
    stdout = StringIO()

    exit_code = main(
        ["basic", "file", str(target), "--format", "json"],
        registry=registry,
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["status"] == "success"
    assert payload["result"]["results"]["basic.file"]["data"]["size"] == 8


def test_basic_module_command_runs_available_basic_analysis(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"\x7fELF\x02\x01\x01payload")
    stdout = StringIO()

    exit_code = main(["basic", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["status"] == "success"
    assert payload["result"]["requested_analyzers"] == ["basic.file"]
    assert payload["result"]["resolved_analyzers"] == ["basic.file"]
    assert payload["result"]["results"]["basic.file"]["data"]["format"] == "elf"


def test_cli_resolves_analyzers_from_profile(tmp_path):
    from soinsight.core.profiles import ProfileRegistry, ScanProfile

    target = tmp_path / "sample.so"
    target.write_bytes(b"profile")
    registry = AnalyzerRegistry()
    registry.register(FrameworkAnalyzer())
    profiles = ProfileRegistry()
    profiles.register(ScanProfile("quick", "Quick", ("basic.file",)))
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
    assert payload["result"]["resolved_analyzers"] == ["basic.file"]


def test_cli_lists_product_modules():
    stdout = StringIO()

    exit_code = main(["modules", "list", "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert [module["id"] for module in payload] == [
        "basic",
        "advanced",
        "security",
        "dynamic",
        "ai",
        "automation",
    ]
    assert payload[0]["capabilities"][0]["id"] == "basic.file"


def test_cli_expands_product_module_for_scan(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"module")
    stdout = StringIO()

    exit_code = main(
        ["scan", str(target), "--module", "security", "--format", "json"],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ANALYSIS_PLAN_ERROR"
    assert "security.hardening" in payload["diagnostics"][0]["message"]


def test_main_help_hides_development_compatibility_aliases():
    stdout = StringIO()

    exit_code = main([], stdout=stdout)

    help_text = stdout.getvalue()
    assert exit_code == 0
    assert "==SUPPRESS==" not in help_text
    assert "    basic" in help_text
    assert "    automation" in help_text
    assert "    file" not in help_text
    assert "    diff" not in help_text


@dataclass
class SecurityAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="security.hardening",
        name="Security Test Analyzer",
        version="1.0.0",
    )

    def analyze(self, target, context):
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"config": context.config.extra},
        )


def _test_registry():
    registry = AnalyzerRegistry()
    registry.register(FrameworkAnalyzer())
    registry.register(SecurityAnalyzer())
    return registry


def test_cli_manages_yaml_config_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("SOINSIGHT_CONFIG_DIR", str(tmp_path / "configs"))

    stdout = StringIO()
    assert main(["config", "create", "quick"], stdout=stdout) == 0
    assert "Created configuration 'quick'" in stdout.getvalue()

    assert main(
        ["config", "set", "quick", "analysis.modules.basic", "[file]"],
        stdout=StringIO(),
    ) == 0
    assert main(["config", "validate", "quick"], stdout=StringIO()) == 0
    assert main(["config", "use", "quick"], stdout=StringIO()) == 0

    current = StringIO()
    assert main(["config", "current"], stdout=current) == 0
    assert current.getvalue().startswith("quick\t")

    shown = StringIO()
    assert main(["config", "show", "quick"], stdout=shown) == 0
    payload = __import__("yaml").safe_load(shown.getvalue())
    assert payload["analysis"]["modules"]["basic"] == ["file"]

    listed = StringIO()
    assert main(["config", "list", "--format", "json"], stdout=listed) == 0
    assert json.loads(listed.getvalue())[0]["active"] is True

    assert main(["config", "clear"], stdout=StringIO()) == 0


def test_scan_uses_explicit_yaml_selection_runtime_options_and_output(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"yaml")
    config = tmp_path / "scan.yaml"
    config.write_text(
        """schema_version: 1
name: yaml-scan
analysis:
  modules:
    basic: [file]
runtime:
  jobs: 3
output:
  format: json
capability_options:
  basic.file:
    mode: detailed
""",
        encoding="utf-8",
    )
    stdout = StringIO()

    exit_code = main(
        ["scan", str(target), "--config", str(config)],
        registry=_test_registry(),
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == ["basic.file"]
    result_config = payload["result"]["results"]["basic.file"]["data"]["config"]
    assert result_config["analysis_config"] == "yaml-scan"
    assert result_config["capability_options"]["basic.file"]["mode"] == "detailed"


def test_scan_uses_active_config_and_merges_cli_enable(tmp_path, monkeypatch):
    monkeypatch.setenv("SOINSIGHT_CONFIG_DIR", str(tmp_path / "configs"))
    target = tmp_path / "sample.so"
    target.write_bytes(b"active")
    assert main(["config", "create", "active"], stdout=StringIO()) == 0
    assert main(
        ["config", "set", "active", "analysis.modules", "{basic: [file]}"],
        stdout=StringIO(),
    ) == 0
    assert main(["config", "use", "active"], stdout=StringIO()) == 0
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(target),
            "--enable",
            "security.hardening",
            "--format",
            "json",
        ],
        registry=_test_registry(),
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == [
        "basic.file",
        "security.hardening",
    ]


def test_explicit_domain_command_ignores_yaml_selection(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"explicit")
    config = tmp_path / "security.yaml"
    config.write_text(
        """schema_version: 1
name: security
analysis:
  modules:
    security: [hardening]
output:
  format: json
""",
        encoding="utf-8",
    )
    stdout = StringIO()

    exit_code = main(
        ["basic", "file", str(target), "--config", str(config)],
        registry=_test_registry(),
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == ["basic.file"]
