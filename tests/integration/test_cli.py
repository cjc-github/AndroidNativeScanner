from dataclasses import dataclass
from io import StringIO
import json
import shutil

import pytest

from soinsight.cli.main import _display_width, main
from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus
from soinsight.core.runtime.cache import code_version


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


def test_basic_module_command_runs_available_basic_analysis(tmp_path, minimal_elf64_little):
    target = tmp_path / "sample.so"
    target.write_bytes(minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(["basic", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["status"] == "success"
    assert payload["result"]["requested_analyzers"] == [
        "basic.file",
        "basic.elf",
        "basic.symbols",
        "basic.dwarf",
        "basic.types",
        "basic.cpp",
        "basic.disasm",
    ]
    assert payload["result"]["resolved_analyzers"] == [
        "basic.disasm",
        "basic.file",
        "basic.elf",
        "basic.dwarf",
        "basic.symbols",
        "basic.types",
        "basic.cpp",
    ]
    assert payload["result"]["results"]["basic.file"]["data"]["format"] == "elf"
    assert payload["result"]["results"]["basic.elf"]["data"]["type"] == "DYN"


def test_cli_runs_builtin_basic_elf_analyzer(tmp_path, minimal_elf64_little):
    target = tmp_path / "libsample.so"
    target.write_bytes(minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(["basic", "elf", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == ["basic.file", "basic.elf"]
    assert payload["result"]["results"]["basic.elf"]["data"]["machine"] == "x86-64"


def test_cli_runs_first_cross_domain_chain(tmp_path, minimal_elf64_little):
    target = tmp_path / "libsample.so"
    target.write_bytes(minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(["security", "hardening", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == [
        "basic.file",
        "basic.elf",
        "security.hardening",
    ]
    assert "security.hardening" in payload["result"]["results"]


def test_cli_uses_builtin_security_profile(tmp_path, minimal_elf64_little):
    target = tmp_path / "libsample.so"
    target.write_bytes(minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(["scan", str(target), "--profile", "security", "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["profile"] == "security"
    assert payload["result"]["requested_analyzers"] == ["security.hardening"]
    assert payload["result"]["resolved_analyzers"] == [
        "basic.file",
        "basic.elf",
        "security.hardening",
    ]


def test_cli_renders_markdown_and_html_reports(tmp_path, minimal_elf64_little):
    target = tmp_path / "libsample.so"
    target.write_bytes(minimal_elf64_little)

    stdout = StringIO()
    assert main(
        ["scan", str(target), "--profile", "quick", "--format", "markdown"], stdout=stdout
    ) == 0
    markdown = stdout.getvalue()
    assert markdown.startswith("# SOInsight Analysis Report\n")
    assert "## Target" in markdown

    stdout = StringIO()
    assert main(
        ["scan", str(target), "--profile", "quick", "--format", "html"], stdout=stdout
    ) == 0
    html = stdout.getvalue()
    assert html.startswith("<!doctype html>")
    assert "<title>SOInsight Analysis Report</title>" in html


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
        "advanced    高级分析             8  partial",
        "security    安全分析             4  implemented",
        "dynamic     动态分析             5  catalog-only",
        "ai          AI 分析              8  catalog-only",
        "automation  自动化               7  catalog-only",
    ]


def test_cli_shows_module_capabilities_with_status():
    stdout = StringIO()

    exit_code = main(["modules", "show", "basic"], stdout=stdout)

    assert exit_code == 0
    lines = stdout.getvalue().splitlines()
    assert lines[:6] == [
        "Module: basic",
        "Name:   基础分析",
        "Status: partial",
        "",
        "Description:",
        "  建立二进制、ELF、代码结构和统一 IR 的基础事实。",
    ]
    assert lines[7] == "Capabilities:"

    header, *rows = lines[8:]
    assert header.startswith("  COMMAND")
    assert header.endswith("STATUS")

    assert any(row.endswith("implemented") for row in rows)
    assert any(row.endswith("planned") for row in rows)


@pytest.mark.parametrize(
    "module_id",
    ["basic", "advanced", "security", "dynamic", "ai", "automation"],
)
def test_cli_module_capability_table_is_column_aligned(module_id):
    """The STATUS column must line up in every row of every module.

    "security.dangerous-api" is the widest command in the catalog, so a
    hard-coded column width overflows and pushes the row out of alignment with
    the header. Asserting the invariant keeps the table readable as the catalog
    grows.
    """
    stdout = StringIO()

    exit_code = main(["modules", "show", module_id], stdout=stdout)

    assert exit_code == 0
    lines = stdout.getvalue().splitlines()
    header, *rows = lines[lines.index("Capabilities:") + 1 :]

    def status_offset(line: str) -> int:
        return _display_width(line[: line.rindex(" ") + 1])

    offsets = {status_offset(header)} | {status_offset(row) for row in rows}
    assert offsets == {status_offset(header)}, (
        f"{module_id}: STATUS column misaligned\n"
        f"  header offset {status_offset(header)}\n"
        + "\n".join(f"  {status_offset(row)}  {row!r}" for row in rows)
    )


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
        "ID                     VERSION KIND        DEFAULT NAME",
        "advanced.strings       1.0.0   collector   yes     Strings Analyzer",
        "basic.cpp              1.0.0   collector   yes     C++ Recovery Analyzer",
        "basic.disasm           1.0.0   collector   yes     Disassembly Analyzer",
        "basic.dwarf            1.0.0   collector   yes     DWARF Analyzer",
        "basic.elf              1.0.0   collector   yes     ELF Header Analyzer",
        "basic.file             1.0.0   collector   yes     File Analyzer",
        "basic.symbols          1.0.0   collector   yes     Symbol Analyzer",
        "basic.types            1.0.0   collector   yes     Type Recovery Analyzer",
        "security.dangerous-api 1.0.0   detector    yes     Dangerous API Detection",
        "security.hardening     1.0.0   collector   yes     Hardening Analyzer",
        "security.risk          1.0.0   transformer yes     Risk Analyzer",
        "security.vulnerability 1.0.0   detector    yes     Vulnerability Pattern Analyzer",
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
        ["scan", str(target), "--module", "dynamic", "--format", "json"],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ANALYSIS_PLAN_ERROR"
    assert "dynamic.trace" in payload["diagnostics"][0]["message"]


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
    assert "  Registered analyzers   12\n" in output
    assert "\nLegacy tools (V1 pipeline only):\n" in output
    assert "  readelf               " in output
    assert "  nm                    " in output
    assert "  strings               " in output
    # External binutils are optional: the built-in analyzers parse ELF
    # directly, so the status line depends only on the host toolchain.
    assert "\nStatus:\n  " in output
    assert output.splitlines()[-1] in (
        "  ok",
        "  Install binutils if needed: sudo apt-get install binutils",
    )


def test_cli_doctor_reports_missing_legacy_tools_as_info(monkeypatch):
    """Missing binutils downgrade to info: V2 analyzers are pure Python."""
    monkeypatch.setattr(shutil, "which", lambda name: None)
    stdout = StringIO()

    exit_code = main(["doctor"], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert "\nLegacy tools (V1 pipeline only):\n" in output
    assert "\nStatus:\n  info\n" in output
    assert "warning" not in output
    assert "Legacy tools missing: readelf, nm, strings" in output
    assert "legacy V1 pipeline" in output


def test_cli_cache_info_reports_version_scoping(tmp_path):
    cache_dir = tmp_path / "cache"
    active = code_version()
    (cache_dir / active / "sha").mkdir(parents=True)
    (cache_dir / active / "sha" / "keep.json").write_text("{}")
    (cache_dir / ("0" * 16) / "sha").mkdir(parents=True)
    (cache_dir / ("0" * 16) / "sha" / "stale.json").write_text("{}")
    stdout = StringIO()

    exit_code = main(["cache", "info", "--cache-dir", str(cache_dir)], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert f"Cache directory: {cache_dir.resolve()}" in output
    assert f"Code version:     {active}" in output
    assert "Entries:          1 active / 2 total" in output
    assert "Stale versions:   1 (prune to remove)" in output


def test_cli_cache_clean_removes_everything(tmp_path):
    cache_dir = tmp_path / "cache"
    (cache_dir / code_version() / "sha").mkdir(parents=True)
    (cache_dir / code_version() / "sha" / "x.json").write_text("0123456789")
    stdout = StringIO()

    exit_code = main(["cache", "clean", "--cache-dir", str(cache_dir)], stdout=stdout)

    assert exit_code == 0
    assert not cache_dir.exists()
    assert "1 files" in stdout.getvalue()
    assert "10 bytes" in stdout.getvalue()


def test_cli_cache_prune_keeps_active_version_only(tmp_path):
    cache_dir = tmp_path / "cache"
    active = code_version()
    (cache_dir / active / "sha").mkdir(parents=True)
    (cache_dir / active / "sha" / "keep.json").write_text("{}")
    stale = cache_dir / "deadbeefdeadbeef"
    (stale / "sha").mkdir(parents=True)
    (stale / "sha" / "drop.json").write_text("{}")
    stdout = StringIO()

    exit_code = main(["cache", "prune", "--cache-dir", str(cache_dir)], stdout=stdout)

    assert exit_code == 0
    assert (cache_dir / active / "sha" / "keep.json").exists()
    assert not stale.exists()
    assert "Pruned 1 stale version(s): 1 files" in stdout.getvalue()


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


def test_cli_runs_builtin_symbol_analyzer_with_signatures(tmp_path, elf64_with_symbols):
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(["basic", "symbols", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    result = payload["result"]
    assert exit_code == 0
    assert result["requested_analyzers"] == ["basic.symbols"]
    assert result["resolved_analyzers"] == ["basic.file", "basic.elf", "basic.symbols"]

    symbols = result["results"]["basic.symbols"]["data"]
    assert symbols["counts"]["exported_functions"] == 5
    assert symbols["demangled_count"] == 3
    assert symbols["jni_count"] == 2
    assert [record["signature"] for record in symbols["functions"]] == [
        "com.example.Foo.nativeInit",
        "com.example.Foo.nativeInit(int, java.lang.String)",
        "foo::bar(int)",
        "std::vector<int, std::allocator<int> >::push_back(int const&)",
        "android::IBinder::~IBinder()",
    ]


def test_cli_symbol_analysis_renders_human_text(tmp_path, elf64_with_symbols):
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(["basic", "symbols", str(target)], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert "\nSymbols:\n" in output
    assert "  Exported functions   5\n" in output
    assert "  Signatures:\n" in output
    assert "    foo::bar(int)\n" in output
    assert "    com.example.Foo.nativeInit(int, java.lang.String)\n" in output


def test_cli_symbol_analysis_skips_non_elf_target(tmp_path):
    target = tmp_path / "plain.txt"
    target.write_bytes(b"not an elf file")
    stdout = StringIO()

    exit_code = main(["basic", "symbols", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 5
    assert payload["result"]["results"]["basic.elf"]["status"] == "failed"
    assert payload["result"]["results"]["basic.symbols"]["status"] == "skipped"


def test_cli_runs_dangerous_api_chain_and_reports_findings(tmp_path, elf64_with_symbols):
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(
        ["security", "dangerous-api", str(target), "--format", "json"], stdout=stdout
    )

    payload = json.loads(stdout.getvalue())
    result = payload["result"]
    assert exit_code == 0
    assert result["requested_analyzers"] == ["security.dangerous-api"]
    assert result["resolved_analyzers"] == [
        "basic.file",
        "basic.elf",
        "basic.symbols",
        "security.dangerous-api",
    ]
    analysis = result["results"]["security.dangerous-api"]
    assert analysis["status"] == "success"
    # The fixture exports no dangerous API and imports none either.
    assert analysis["data"]["finding_count"] == 0
    assert result["findings"] == []


def test_cli_dangerous_api_reports_findings_as_text(tmp_path):
    """A library importing system() must surface a critical finding."""
    from tests.conftest import build_elf64_with_symbols

    symbols = [
        ("", 0, 3, 0xFFF1, 0, 0),
        ("system", 1, 0, 0, 0, 0),          # imported, untyped
        ("_ZN3foo3barEi", 1, 2, 1, 0x1000, 0x20),
    ]
    target = tmp_path / "libdanger.so"
    target.write_bytes(build_elf64_with_symbols(symbols, with_symtab=False))
    stdout = StringIO()

    exit_code = main(["security", "dangerous-api", str(target)], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert "security.dangerous-api  success" in output
    assert "Dangerous API imported: system" in output


def test_cli_dangerous_api_skips_when_symbols_unavailable(tmp_path):
    """A non-ELF target skips the whole chain instead of failing loudly."""
    target = tmp_path / "plain.txt"
    target.write_bytes(b"not an elf file")
    stdout = StringIO()

    exit_code = main(
        ["security", "dangerous-api", str(target), "--format", "json"], stdout=stdout
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 5
    assert payload["result"]["results"]["basic.elf"]["status"] == "failed"
    assert payload["result"]["results"]["security.dangerous-api"]["status"] == "skipped"


def test_cli_advanced_strings_classifies_and_mints_rules(tmp_path):
    """URL/secret/base64 hits must classify facts and raise security rules."""
    stdout = StringIO()
    target = tmp_path / "plain.txt"
    target.write_bytes(
        "https://api.example.com/v1/login\x00"
        "AIzaSyA1234567890abcdefghijklmnopqrstuvw\x00".encode()
    )

    exit_code = main(
        ["advanced", "strings", str(target), "--format", "json"], stdout=stdout
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["requested_analyzers"] == ["advanced.strings"]
    analysis = payload["result"]["results"]["advanced.strings"]
    assert analysis["status"] == "success"
    assert analysis["data"]["classified"]["url"]["count"] == 1
    assert analysis["data"]["classified"]["sensitive"]["count"] == 1
    rule_ids = [finding["rule_id"] for finding in payload["result"]["findings"]]
    assert "security.hardcoded-url" in rule_ids
    assert "security.sensitive-string.google-api-key" in rule_ids


def test_cli_strings_renders_classified_text(tmp_path):
    stdout = StringIO()
    target = tmp_path / "plain.txt"
    target.write_bytes(b"a plain https://kernel.org sample\x00")

    exit_code = main(["advanced", "strings", str(target)], stdout=stdout)

    output = stdout.getvalue()
    assert exit_code == 0
    assert "advanced.strings" in output
    assert "URL" in output


def test_cli_risk_aggregates_reachable_chain(tmp_path, elf64_with_symbols):
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(
        ["security", "risk", str(target), "--format", "json"], stdout=stdout
    )

    payload = json.loads(stdout.getvalue())
    result = payload["result"]
    assert exit_code == 0
    assert result["requested_analyzers"] == ["security.risk"]
    assert result["resolved_analyzers"] == [
        "advanced.strings",
        "basic.file",
        "basic.elf",
        "basic.symbols",
        "security.hardening",
        "security.dangerous-api",
        "security.risk",
    ]
    risk = result["results"]["security.risk"]
    assert risk["status"] == "success"
    # The fixture has a symbol table but no canary/CFI references, so the
    # hardening analyzer reports both features as missing and the score
    # reflects exactly those two aggregated findings.
    rule_ids = [finding["rule_id"] for finding in result["findings"]]
    assert set(rule_ids) == {
        "security.hardening.missing-stack-canary",
        "security.hardening.missing-cfi",
    }
    # One medium (canary) plus one high (CFI) severity finding aggregate to 13.
    assert risk["data"]["risk_score"] == 13


def test_cli_writes_progress_to_stderr_not_stdout(tmp_path, elf64_with_symbols, capsys):
    """Progress is diagnostic output; stdout must stay pipeable."""
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(
        ["basic", "symbols", str(target), "--no-cache", "--format", "json"],
        stdout=stdout,
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    # stdout holds only the rendered JSON document.
    assert json.loads(stdout.getvalue())["result"]["status"] == "success"
    assert "running basic.file" in captured.err
    assert "basic.file success" in captured.err
    assert "running basic.file" not in stdout.getvalue()


def test_cli_reports_progress_for_cached_analyzers(tmp_path, elf64_with_symbols, capsys):
    """A cache hit skips the scheduler, so it must still be reported."""
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()
    cache_dir = tmp_path / "cache"
    arguments = [
        "basic", "symbols", str(target), "--cache-dir", str(cache_dir),
        "--format", "json",
    ]

    assert main(arguments, stdout=stdout) == 0
    capsys.readouterr()
    assert main(arguments, stdout=stdout) == 0

    captured = capsys.readouterr()
    assert "basic.file success (cache hit)" in captured.err
    assert "running basic.file" not in captured.err


def test_cli_quiet_suppresses_progress(tmp_path, elf64_with_symbols, capsys):
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(
        ["basic", "symbols", str(target), "--quiet", "--format", "json"], stdout=stdout
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "running basic.file" not in captured.err
    assert json.loads(stdout.getvalue())["result"]["status"] == "success"


def test_cli_dwarf_enriches_symbol_signatures_with_parameter_names(tmp_path):
    """DWARF supplies what the dynamic symbol table cannot: parameter names."""
    from tests.conftest import build_dwarf_sections, build_elf64_with_symbols

    symbols = [
        ("", 0, 3, 0xFFF1, 0, 0),
        ("add", 1, 2, 1, 0x1000, 0x40),
        ("_ZN7MyClass7processEPKci", 1, 2, 1, 0x1100, 0x60),
    ]
    target = tmp_path / "libjoined.so"
    target.write_bytes(
        build_elf64_with_symbols(
            symbols, with_symtab=False, extra_sections=build_dwarf_sections()
        )
    )
    stdout = StringIO()

    exit_code = main(
        [
            "scan", str(target), "--no-cache",
            "--enable", "basic.file,basic.elf,basic.symbols,basic.dwarf",
        ],
        stdout=stdout,
    )

    output = stdout.getvalue()
    assert exit_code == 0
    assert "  With parameter names 2" in output
    assert "int add(int a, int b)" in output
    assert "int MyClass::process(char const* buffer, unsigned int length)" in output


def test_cli_dwarf_analysis_reports_missing_debug_information(
    tmp_path, elf64_with_symbols
):
    target = tmp_path / "libsample.so"
    target.write_bytes(elf64_with_symbols)
    stdout = StringIO()

    exit_code = main(
        ["basic", "dwarf", str(target), "--no-cache", "--format", "json"], stdout=stdout
    )

    payload = json.loads(stdout.getvalue())
    analysis = payload["result"]["results"]["basic.dwarf"]
    assert exit_code == 0
    assert analysis["status"] == "success"
    assert analysis["data"]["has_debug_info"] is False
    assert analysis["data"]["functions"] == []


def test_cli_reports_unimplemented_capability_with_try_suggestions(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["basic", "callgraph", str(target)], stdout=stdout)

    assert exit_code == 3
    assert stdout.getvalue().splitlines() == [
        "Error: capability is not implemented",
        "",
        "Capability:",
        "  basic.callgraph",
        "",
        "Reason:",
        "  Analyzer not found: basic.callgraph",
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

    exit_code = main(["basic", "callgraph", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ANALYSIS_PLAN_ERROR"
    assert "basic.callgraph" in payload["diagnostics"][0]["message"]


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

    exit_code = main(["basic", "callgraph", str(target), "--quiet"], stdout=stdout)

    assert exit_code == 3
    assert "Error: capability is not implemented" in stdout.getvalue()
    assert "Try:" in stdout.getvalue()


@dataclass
class FailingAnalyzer(Analyzer):
    metadata: AnalyzerMetadata

    def analyze(self, target, context):
        raise RuntimeError("boom")


def test_cli_exit_code_reflects_partial_result(tmp_path):
    target = tmp_path / "plain.txt"
    target.write_bytes(b"not an elf file")
    stdout = StringIO()

    exit_code = main(["basic", "elf", str(target)], stdout=stdout)

    assert exit_code == 5


def test_cli_exit_code_reflects_failed_result(tmp_path):
    registry = AnalyzerRegistry()
    registry.register(
        FailingAnalyzer(AnalyzerMetadata(id="basic.file", name="File", version="1"))
    )
    target = tmp_path / "sample.so"
    target.write_bytes(b"data")
    stdout = StringIO()

    exit_code = main(["basic", "file", str(target)], registry=registry, stdout=stdout)

    assert exit_code == 4


def test_modules_list_uses_compact_layout_for_narrow_terminal(monkeypatch):
    monkeypatch.setattr("shutil.get_terminal_size", lambda fallback=None: __import__("os").terminal_size((48, 24)))
    stdout = TtyStringIO()

    exit_code = main(["modules", "list", "--no-color"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines()[0] == "MODULE      STATUS"
    assert "basic       partial" in stdout.getvalue()
    assert "CAPABILITIES" not in stdout.getvalue()
