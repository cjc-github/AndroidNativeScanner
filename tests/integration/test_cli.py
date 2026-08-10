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


def _minimal_elf64_little() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = (
        (3).to_bytes(2, "little")
        + (62).to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (0x401000).to_bytes(8, "little")
        + (64).to_bytes(8, "little")
        + (1024).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + (8).to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + (12).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
    )
    return ident + header


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
    target.write_bytes(_minimal_elf64_little())
    stdout = StringIO()

    exit_code = main(["basic", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["status"] == "success"
    assert payload["result"]["requested_analyzers"] == ["basic.file", "basic.elf"]
    assert payload["result"]["resolved_analyzers"] == ["basic.file", "basic.elf"]
    assert payload["result"]["results"]["basic.file"]["data"]["format"] == "elf"
    assert payload["result"]["results"]["basic.elf"]["data"]["type"] == "DYN"


def test_cli_runs_builtin_basic_elf_analyzer(tmp_path):
    target = tmp_path / "libsample.so"
    target.write_bytes(_minimal_elf64_little())
    stdout = StringIO()

    exit_code = main(["basic", "elf", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == ["basic.file", "basic.elf"]
    assert payload["result"]["results"]["basic.elf"]["data"]["machine"] == "x86-64"


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


def test_cli_lists_product_modules_with_status_column():
    stdout = StringIO()

    exit_code = main(["modules", "list"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines() == [
        "MODULE      NAME      CAPABILITIES  STATUS",
        "basic       基础分析            10  partial",
        "advanced    高级分析             8  catalog-only",
        "security    安全分析             4  catalog-only",
        "dynamic     动态分析             5  catalog-only",
        "ai          AI 分析              8  catalog-only",
        "automation  自动化               7  catalog-only",
    ]


def test_cli_shows_module_capabilities_with_status():
    stdout = StringIO()

    exit_code = main(["modules", "show", "basic"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines() == [
        "Module: basic",
        "Name:   基础分析",
        "Status: partial",
        "",
        "Description:",
        "  建立二进制、ELF、代码结构和统一 IR 的基础事实。",
        "",
        "Capabilities:",
        "  COMMAND     ID                NAME             STATUS",
        "  file        basic.file        文件分析         implemented",
        "  elf         basic.elf         ELF 解析         implemented",
        "  symbols     basic.symbols     Symbol 解析      planned",
        "  dwarf       basic.dwarf       DWARF 解析       planned",
        "  types       basic.types       类型恢复         planned",
        "  cpp         basic.cpp         C++ 恢复         planned",
        "  disasm      basic.disasm      反汇编           planned",
        "  cfg         basic.cfg         CFG 恢复         planned",
        "  callgraph   basic.callgraph   Call Graph 恢复  planned",
        "  dataflow    basic.dataflow    Data Flow 分析   planned",
    ]


def test_cli_lists_product_modules_as_json():
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


def test_cli_lists_plugins_as_table():
    stdout = StringIO()

    exit_code = main(["plugins", "list"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines() == [
        "ID          VERSION  KIND       DEFAULT  NAME",
        "basic.elf   1.0.0    collector  yes      ELF Header Analyzer",
        "basic.file  1.0.0    collector  yes      File Analyzer",
    ]


def test_cli_lists_empty_plugins_with_catalog_hint():
    registry = AnalyzerRegistry()
    stdout = StringIO()

    exit_code = main(["plugins", "list"], registry=registry, stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines() == [
        "No analyzers registered.",
        "",
        "Product capabilities may still appear under `soinsight modules`.",
        "Use `soinsight modules list` to inspect the catalog.",
    ]


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


def test_main_help_groups_commands_and_hides_development_aliases():
    stdout = StringIO()

    exit_code = main([], stdout=stdout)

    help_text = stdout.getvalue()
    assert exit_code == 0
    assert help_text.startswith("SOInsight 2.0.0.dev0\n")
    assert "Usage:\n  soinsight <command> [options]" in help_text
    assert "Analysis domains:" in help_text
    assert "  basic       Basic file, ELF, symbol and code-structure analysis" in help_text
    assert "Project commands:" in help_text
    assert "  modules     Inspect product capability catalog" in help_text
    assert "Use:\n  soinsight <command> --help" in help_text
    assert "==SUPPRESS==" not in help_text
    assert "\n  file" not in help_text
    assert "\n  diff" not in help_text


def test_explicit_main_help_uses_grouped_output():
    stdout = StringIO()

    exit_code = main(["--help"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().startswith("SOInsight 2.0.0.dev0\n")
    assert "Analysis domains:" in stdout.getvalue()
    assert "usage: soinsight" not in stdout.getvalue()


def test_cli_doctor_outputs_grouped_health_check():
    stdout = StringIO()

    exit_code = main(["doctor"], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert output.startswith("SOInsight doctor\n\n")
    assert "Core:\n" in output
    assert "  Version               2.0.0.dev0\n" in output
    assert "  Python                " in output
    assert "  Executable            " in output
    assert "\nCapabilities:\n" in output
    assert "  Product modules        6\n" in output
    assert "  Registered analyzers   2\n" in output
    assert "\nExternal tools:\n" in output
    assert "  readelf               " in output
    assert "  nm                    " in output
    assert "  strings               " in output
    assert "\nStatus:\n  ok\n" in output


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


def test_cli_reports_unimplemented_capability_with_try_suggestions(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["basic", "symbols", str(target)], stdout=stdout)

    assert exit_code == 3
    assert stdout.getvalue().splitlines() == [
        "Error: capability is not implemented",
        "",
        "Capability:",
        "  basic.symbols",
        "",
        "Reason:",
        "  Analyzer not found: basic.symbols",
        "",
        "Try:",
        "  soinsight modules show basic",
        "  soinsight basic file <target>",
        "",
        "Exit code: 3",
    ]


def test_cli_reports_unimplemented_capability_as_json(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["basic", "symbols", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ANALYSIS_PLAN_ERROR"
    assert "basic.symbols" in payload["diagnostics"][0]["message"]


def test_cli_renders_basic_file_analysis_as_human_text(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"\x7fELF\x02\x01\x01payload")
    stdout = StringIO()

    exit_code = main(["basic", "file", str(target)], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert "Target:\n" in output
    assert f"  Path       {target}\n" in output
    assert "  Size       14 B\n" in output
    assert "  SHA-256    " in output
    assert "\nAnalysis:\n" in output
    assert "  basic.file  success" in output
    assert "\nFile facts:\n" in output
    assert "  Format      elf\n" in output
    assert "  Magic       7f454c4602010170\n" in output
    assert "  Name        sample.so\n" in output
    assert "\nFindings:\n  none\n" in output


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


class TtyStringIO(StringIO):
    def isatty(self):
        return True


def test_modules_list_uses_color_on_tty():
    stdout = TtyStringIO()

    exit_code = main(["modules", "list"], stdout=stdout)

    assert exit_code == 0
    assert "\x1b[" in stdout.getvalue()
    assert "partial" in stdout.getvalue()


def test_no_color_disables_tty_color():
    stdout = TtyStringIO()

    exit_code = main(["modules", "list", "--no-color"], stdout=stdout)

    assert exit_code == 0
    assert "\x1b[" not in stdout.getvalue()
    assert "partial" in stdout.getvalue()


def test_quiet_success_suppresses_analysis_text_output(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"\x7fELF\x02\x01\x01payload")
    stdout = StringIO()

    exit_code = main(["basic", "file", str(target), "--quiet"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue() == ""


def test_quiet_failure_keeps_actionable_error(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["basic", "symbols", str(target), "--quiet"], stdout=stdout)

    assert exit_code == 3
    assert "Error: capability is not implemented" in stdout.getvalue()
    assert "Try:" in stdout.getvalue()


def test_modules_list_uses_compact_layout_for_narrow_terminal(monkeypatch):
    monkeypatch.setattr("shutil.get_terminal_size", lambda fallback=None: __import__("os").terminal_size((48, 24)))
    stdout = TtyStringIO()

    exit_code = main(["modules", "list", "--no-color"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines()[0] == "MODULE      STATUS"
    assert "basic       partial" in stdout.getvalue()
    assert "CAPABILITIES" not in stdout.getvalue()
