# CLI Output Specification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement SOInsight CLI text output improvements defined in `docs/cli-output-spec.md` for P0 and P1 while preserving JSON compatibility.

**Architecture:** Keep CLI output decisions in `src/soinsight/cli/main.py` and renderer-specific analysis formatting in `src/soinsight/renderers/text_renderer.py`. Add small formatting helpers for display-width padding and status derivation instead of introducing new dependencies.

**Tech Stack:** Python 3.10+, argparse, dataclasses, pytest integration tests through `soinsight.cli.main.main()`.

## Global Constraints

- `text` output uses spaces, not tab characters, for alignment.
- `json` output remains stable and must not change for modules/plugins/doctor unless explicitly covered by tests.
- Chinese display width is treated as double-width for text alignment.
- Capability status values are exactly `implemented` and `planned`.
- Module status values are exactly `implemented`, `partial`, and `catalog-only`.
- No new runtime dependency is allowed for table formatting or terminal color.
- Error output must include what happened, reason, suggested commands, and stable exit code.
- All CLI behavior changes must be covered by integration tests using real `main()` calls.

---

## File Structure

- `docs/cli-output-spec.md` — source specification already written; update only if implementation reveals a necessary clarification.
- `src/soinsight/cli/main.py` — command-level text output for help, modules, plugins, doctor, and selection/plan errors.
- `src/soinsight/renderers/text_renderer.py` — human-oriented scan result rendering.
- `tests/integration/test_cli.py` — integration tests for CLI text and JSON behavior.

---

### Task 1: Shared CLI text formatting and status helpers

**Files:**
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `AnalyzerRegistry.contains(analyzer_id: str) -> bool`, `AnalyzerRegistry.list() -> list[AnalyzerMetadata]`, `ModuleCatalog.list() -> list[ModuleDefinition]`.
- Produces:
  - `_display_width(text: str) -> int`
  - `_pad_display(text: str, width: int) -> str`
  - `_capability_status(capability_id: str, registry: AnalyzerRegistry) -> str`
  - `_module_status(module, registry: AnalyzerRegistry) -> str`

- [ ] **Step 1: Write failing tests for status helper behavior through CLI output**

Add this test after the existing modules tests in `tests/integration/test_cli.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_lists_product_modules_with_status_column -q
```

Expected: FAIL because current output has no header and no `STATUS` column.

- [ ] **Step 3: Implement status helpers**

In `src/soinsight/cli/main.py`, keep the existing `_display_width()` and `_pad_display()` helpers if already present. Add or update these functions near `_module_payload()`:

```python
def _capability_status(capability_id: str, registry: AnalyzerRegistry) -> str:
    return "implemented" if registry.contains(capability_id) else "planned"


def _module_status(module, registry: AnalyzerRegistry) -> str:
    capability_ids = module.analyzer_ids
    implemented = sum(1 for analyzer_id in capability_ids if registry.contains(analyzer_id))
    if implemented == 0:
        return "catalog-only"
    if implemented == len(capability_ids):
        return "implemented"
    return "partial"
```

- [ ] **Step 4: Thread registry into modules handler**

Change `_handle_modules` signature from:

```python
def _handle_modules(args: argparse.Namespace, catalog: ModuleCatalog, stdout: TextIO) -> int:
```

to:

```python
def _handle_modules(
    args: argparse.Namespace,
    catalog: ModuleCatalog,
    registry: AnalyzerRegistry,
    stdout: TextIO,
) -> int:
```

Update the caller in `main()` from:

```python
return _handle_modules(args, module_catalog, output_stream)
```

to:

```python
return _handle_modules(args, module_catalog, analyzer_registry, output_stream)
```

- [ ] **Step 5: Run test to verify it still fails for output only**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_lists_product_modules_with_status_column -q
```

Expected: FAIL because `_handle_modules` output has not yet been changed.

---

### Task 2: Implement `modules list` and `modules show` status output

**Files:**
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `_pad_display`, `_module_status`, `_capability_status` from Task 1.
- Produces: Text output matching `docs/cli-output-spec.md` sections 5 and 6.

- [ ] **Step 1: Add failing test for `modules show basic` status output**

Add this test after `test_cli_lists_product_modules_with_status_column`:

```python
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
        "  file        basic.file        文件分析          implemented",
        "  elf         basic.elf         ELF 解析          planned",
        "  symbols     basic.symbols     Symbol 解析      planned",
        "  dwarf       basic.dwarf       DWARF 解析        planned",
        "  types       basic.types       类型恢复          planned",
        "  cpp         basic.cpp         C++ 恢复          planned",
        "  disasm      basic.disasm      反汇编            planned",
        "  cfg         basic.cfg         CFG 恢复          planned",
        "  callgraph   basic.callgraph   Call Graph 恢复   planned",
        "  dataflow    basic.dataflow    Data Flow 分析    planned",
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_cli.py::test_cli_lists_product_modules_with_status_column \
  tests/integration/test_cli.py::test_cli_shows_module_capabilities_with_status -q
```

Expected: both tests FAIL until text output is implemented.

- [ ] **Step 3: Implement `modules list` text output**

In `_handle_modules`, replace the current text loop for `args.action != "show"` with:

```python
    if args.action != "show":
        stdout.write("MODULE      NAME      CAPABILITIES  STATUS\n")
        for module in selected:
            module_id = _pad_display(module.id, 12)
            module_name = _pad_display(module.name, 10)
            count = f"{len(module.capabilities):>12}"
            status = _module_status(module, registry)
            stdout.write(f"{module_id}{module_name}{count}  {status}\n")
        return 0
```

- [ ] **Step 4: Implement `modules show` text output**

In `_handle_modules`, add the `show` branch before returning:

```python
    module = selected[0]
    stdout.write(f"Module: {module.id}\n")
    stdout.write(f"Name:   {module.name}\n")
    stdout.write(f"Status: {_module_status(module, registry)}\n")
    stdout.write("\n")
    stdout.write("Description:\n")
    stdout.write(f"  {module.description}\n")
    stdout.write("\n")
    stdout.write("Capabilities:\n")
    stdout.write("  COMMAND     ID                NAME             STATUS\n")
    for capability in module.capabilities:
        command = _pad_display(capability.command, 12)
        capability_id = _pad_display(capability.id, 18)
        name = _pad_display(capability.name, 17)
        status = _capability_status(capability.id, registry)
        stdout.write(f"  {command}{capability_id}{name}{status}\n")
    return 0
```

- [ ] **Step 5: Verify module text tests pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_cli.py::test_cli_lists_product_modules_with_status_column \
  tests/integration/test_cli.py::test_cli_shows_module_capabilities_with_status -q
```

Expected: PASS.

- [ ] **Step 6: Verify modules JSON compatibility**

Add or keep a JSON-specific test:

```python
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
```

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_lists_product_modules_as_json -q
```

Expected: PASS.

- [ ] **Step 7: Commit Task 1 and 2**

```bash
git add src/soinsight/cli/main.py tests/integration/test_cli.py docs/cli-output-spec.md
git commit -m "feat: show module implementation status"
```

---

### Task 3: Table-format `plugins list`

**Files:**
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `AnalyzerRegistry.list()`, `AnalyzerMetadata.kind`, `AnalyzerMetadata.default_enabled`.
- Produces: Text table for registered analyzers and helpful empty-state text.

- [ ] **Step 1: Add failing test for populated plugins table**

Add this test near existing plugins tests or after module tests:

```python
def test_cli_lists_plugins_as_table():
    stdout = StringIO()

    exit_code = main(["plugins", "list"], stdout=stdout)

    assert exit_code == 0
    assert stdout.getvalue().splitlines() == [
        "ID          VERSION  KIND       DEFAULT  NAME",
        "basic.file  1.0.0    collector  yes      File Analyzer",
    ]
```

- [ ] **Step 2: Add failing test for empty plugins hint**

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_cli.py::test_cli_lists_plugins_as_table \
  tests/integration/test_cli.py::test_cli_lists_empty_plugins_with_catalog_hint -q
```

Expected: FAIL because current output is tab-separated and empty-state copy differs.

- [ ] **Step 4: Implement plugin table output**

In `_handle_plugins`, replace the text branch with:

```python
    elif metadata:
        stdout.write("ID          VERSION  KIND       DEFAULT  NAME\n")
        for item in metadata:
            analyzer_id = _pad_display(item.id, 12)
            version = _pad_display(item.version, 9)
            kind = _pad_display(item.kind.value, 11)
            default = _pad_display("yes" if item.default_enabled else "no", 9)
            stdout.write(f"{analyzer_id}{version}{kind}{default}{item.name}\n")
    else:
        stdout.write("No analyzers registered.\n")
        stdout.write("\n")
        stdout.write("Product capabilities may still appear under `soinsight modules`.\n")
        stdout.write("Use `soinsight modules list` to inspect the catalog.\n")
```

- [ ] **Step 5: Verify plugin tests pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_cli.py::test_cli_lists_plugins_as_table \
  tests/integration/test_cli.py::test_cli_lists_empty_plugins_with_catalog_hint -q
```

Expected: PASS.

- [ ] **Step 6: Verify plugins JSON compatibility**

Run:

```bash
PYTHONPATH=src python3 -m soinsight plugins list --format json
```

Expected: JSON object list still includes `id`, `version`, `kind`, and `requires`.

- [ ] **Step 7: Commit**

```bash
git add src/soinsight/cli/main.py tests/integration/test_cli.py
git commit -m "feat: format plugins output as table"
```

---

### Task 4: Actionable text errors for unimplemented capabilities

**Files:**
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `_selection_error(...)`, `ApplicationResponse`, `Diagnostic`.
- Produces: Text error output with title, reason, suggestions, and exit code while leaving JSON error output structured.

- [ ] **Step 1: Add failing test for unimplemented capability error**

Replace or update the existing `test_cli_reports_unregistered_analyzer` with:

```python
def test_cli_reports_unimplemented_capability_with_try_suggestions(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["basic", "elf", str(target)], stdout=stdout)

    assert exit_code == 3
    assert stdout.getvalue().splitlines() == [
        "Error: capability is not implemented",
        "",
        "Capability:",
        "  basic.elf",
        "",
        "Reason:",
        "  Analyzer not found: basic.elf",
        "",
        "Try:",
        "  soinsight modules show basic",
        "  soinsight basic file <target>",
        "",
        "Exit code: 3",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_reports_unimplemented_capability_with_try_suggestions -q
```

Expected: FAIL because current text renderer prints `Diagnostics:`.

- [ ] **Step 3: Add error rendering helper**

In `src/soinsight/cli/main.py`, add:

```python
def _render_text_error(response: ApplicationResponse) -> str | None:
    if response.result is not None or not response.diagnostics:
        return None
    diagnostic = response.diagnostics[0]
    if diagnostic.code == "ANALYSIS_PLAN_ERROR" and "Analyzer not found:" in diagnostic.message:
        analyzer_id = diagnostic.message.split("Analyzer not found:", 1)[1].strip()
        module_id = analyzer_id.split(".", 1)[0] if "." in analyzer_id else "basic"
        return (
            "Error: capability is not implemented\n"
            "\n"
            "Capability:\n"
            f"  {analyzer_id}\n"
            "\n"
            "Reason:\n"
            f"  {diagnostic.message}\n"
            "\n"
            "Try:\n"
            f"  soinsight modules show {module_id}\n"
            "  soinsight basic file <target>\n"
            "\n"
            f"Exit code: {response.exit_code}\n"
        )
    return None
```

- [ ] **Step 4: Use error helper in `_render_response` for text only**

Change `_render_response` to:

```python
def _render_response(
    response: ApplicationResponse,
    output_format: str,
    output: str | None,
    renderers: RendererRegistry,
    stdout: TextIO,
) -> int:
    if output_format == "text":
        text_error = _render_text_error(response)
        if text_error is not None:
            _write_output(text_error, output, stdout)
            return response.exit_code
    text = renderers.get(output_format).render(response)
    _write_output(text, output, stdout)
    return response.exit_code
```

- [ ] **Step 5: Verify error test passes**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_reports_unimplemented_capability_with_try_suggestions -q
```

Expected: PASS.

- [ ] **Step 6: Verify JSON errors remain JSON**

Add this test:

```python
def test_cli_reports_unimplemented_capability_as_json(tmp_path):
    target = tmp_path / "sample.so"
    target.write_bytes(b"test")
    stdout = StringIO()

    exit_code = main(["basic", "elf", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ANALYSIS_PLAN_ERROR"
    assert "Analyzer not found: basic.elf" in payload["diagnostics"][0]["message"]
```

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_reports_unimplemented_capability_as_json -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/soinsight/cli/main.py tests/integration/test_cli.py
git commit -m "feat: add actionable CLI error output"
```

---

### Task 5: Custom grouped main help

**Files:**
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `__version__`, `ModuleCatalog`.
- Produces: `_render_main_help(catalog: ModuleCatalog) -> str`.

- [ ] **Step 1: Add failing test for grouped help**

Update `test_main_help_hides_development_compatibility_aliases` to:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_main_help_groups_commands_and_hides_development_aliases -q
```

Expected: FAIL because current help is argparse default.

- [ ] **Step 3: Implement `_render_main_help`**

Add near `build_parser`:

```python
def _render_main_help() -> str:
    return (
        f"SOInsight {__version__}\n"
        "Linux/Android ELF analysis toolbox\n"
        "\n"
        "Usage:\n"
        "  soinsight <command> [options]\n"
        "\n"
        "Analysis domains:\n"
        "  basic       Basic file, ELF, symbol and code-structure analysis\n"
        "  advanced    Strings, constants, compiler and obfuscation analysis\n"
        "  security    Hardening, dangerous API and vulnerability analysis\n"
        "  dynamic     Authorized runtime tracing and coverage\n"
        "  ai          Evidence-based AI assistance\n"
        "  automation  Diff, fuzzing, reports and workflow automation\n"
        "\n"
        "Project commands:\n"
        "  scan        Run a composed analysis plan\n"
        "  modules     Inspect product capability catalog\n"
        "  plugins     Inspect registered analyzers\n"
        "  config      Manage YAML analysis configurations\n"
        "  doctor      Inspect local environment\n"
        "  report      Validate or display JSON result\n"
        "  cache       Inspect cache location\n"
        "\n"
        "Use:\n"
        "  soinsight <command> --help\n"
    )
```

- [ ] **Step 4: Use custom help when no command is provided**

In `main()`, change:

```python
if not args.command:
    parser.print_help(file=output_stream)
    return 0
```

to:

```python
if not args.command:
    output_stream.write(_render_main_help())
    return 0
```

- [ ] **Step 5: Verify help test passes**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_main_help_groups_commands_and_hides_development_aliases -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/soinsight/cli/main.py tests/integration/test_cli.py
git commit -m "feat: group main CLI help output"
```

---

### Task 6: Health-check style `doctor` output

**Files:**
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `shutil.which`, `sys.version`, `sys.executable`, `AnalyzerRegistry.list()`, `ModuleCatalog.list()`.
- Produces: Grouped `doctor` text output.

- [ ] **Step 1: Add failing test for grouped doctor output**

Add:

```python
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
    assert "  Registered analyzers   1\n" in output
    assert "\nExternal tools:\n" in output
    assert "  readelf               " in output
    assert "  nm                    " in output
    assert "  strings               " in output
    assert "\nStatus:\n  ok\n" in output
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_doctor_outputs_grouped_health_check -q
```

Expected: FAIL because current doctor is flat.

- [ ] **Step 3: Implement grouped doctor output**

In `_handle_doctor`, replace the text branch with:

```python
    else:
        missing_tools = [name for name, path in payload["legacy_tools"].items() if not path]
        stdout.write("SOInsight doctor\n")
        stdout.write("\n")
        stdout.write("Core:\n")
        stdout.write(f"  Version               {payload['soinsight_version']}\n")
        stdout.write(f"  Python                {payload['python_version']}\n")
        stdout.write(f"  Executable            {payload['python_executable']}\n")
        stdout.write("\n")
        stdout.write("Capabilities:\n")
        stdout.write(f"  Product modules        {payload['product_modules']}\n")
        stdout.write(f"  Registered analyzers   {payload['registered_analyzers']}\n")
        stdout.write("\n")
        stdout.write("External tools:\n")
        for name, path in payload["legacy_tools"].items():
            tool = _pad_display(name, 22)
            status = _pad_display("ok" if path else "missing", 9)
            stdout.write(f"  {tool}{status}{path or ''}\n")
        stdout.write("\n")
        stdout.write("Status:\n")
        stdout.write(f"  {'warning' if missing_tools else 'ok'}\n")
        if missing_tools:
            stdout.write("\n")
            stdout.write("Hint:\n")
            stdout.write("  Install binutils: sudo apt-get install binutils\n")
```

- [ ] **Step 4: Verify doctor test passes**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_doctor_outputs_grouped_health_check -q
```

Expected: PASS.

- [ ] **Step 5: Verify doctor JSON compatibility**

Run:

```bash
PYTHONPATH=src python3 -m soinsight doctor --format json
```

Expected: JSON still includes `soinsight_version`, `python_version`, `python_executable`, `product_modules`, `registered_analyzers`, and `legacy_tools`.

- [ ] **Step 6: Commit**

```bash
git add src/soinsight/cli/main.py tests/integration/test_cli.py
git commit -m "feat: format doctor as health check"
```

---

### Task 7: Human-oriented analysis text renderer

**Files:**
- Modify: `src/soinsight/renderers/text_renderer.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `ApplicationResponse.result`, `ScanResult.results`, `AnalysisResult.data`.
- Produces: Grouped text scan output with `Target`, `Analysis`, optional `File facts`, `Findings`, and `Diagnostics` sections.

- [ ] **Step 1: Add failing test for `basic file` text output**

Add:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_renders_basic_file_analysis_as_human_text -q
```

Expected: FAIL because current renderer shows framework summary only.

- [ ] **Step 3: Implement byte formatting helper**

In `src/soinsight/renderers/text_renderer.py`, add above `TextRenderer`:

```python
def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"
```

- [ ] **Step 4: Implement grouped scan result rendering**

Replace the `if response.result is not None:` block in `TextRenderer.render()` with:

```python
        if response.result is not None:
            result = response.result
            lines.extend(
                [
                    "Target:",
                    f"  Path       {result.target.path}",
                    f"  Size       {_format_bytes(result.target.size)}",
                    f"  SHA-256    {result.target.sha256}",
                    "",
                    "Analysis:",
                ]
            )
            for analyzer_id in result.resolved_analyzers:
                analyzer_result = result.results.get(analyzer_id)
                if analyzer_result is None:
                    continue
                lines.append(
                    f"  {analyzer_id}  {analyzer_result.status.value}  "
                    f"{analyzer_result.duration_ms} ms"
                )
            file_result = result.results.get("basic.file")
            if file_result is not None and file_result.data:
                lines.extend(
                    [
                        "",
                        "File facts:",
                        f"  Format      {file_result.data.get('format', 'unknown')}",
                        f"  Magic       {file_result.data.get('magic', '')}",
                        f"  Name        {file_result.data.get('name', result.target.name)}",
                    ]
                )
            lines.extend(["", "Findings:"])
            if result.findings:
                for finding in result.findings:
                    lines.append(f"  - {finding.title}")
            else:
                lines.append("  none")
            diagnostics = result.diagnostics
```

Keep the existing diagnostics block below it so diagnostics still render after scan output.

- [ ] **Step 5: Verify renderer test passes**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_renders_basic_file_analysis_as_human_text -q
```

Expected: PASS.

- [ ] **Step 6: Verify JSON scan output compatibility**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_runs_registered_analyzer_and_emits_json -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/soinsight/renderers/text_renderer.py tests/integration/test_cli.py
git commit -m "feat: render analysis results for humans"
```

---

### Task 8: Final verification and documentation cross-check

**Files:**
- Modify: `docs/cli-reference.md` if existing examples now contradict output behavior.
- Test: full test suite.

**Interfaces:**
- Consumes: all tasks above.
- Produces: verified CLI output implementation aligned with `docs/cli-output-spec.md`.

- [ ] **Step 1: Run representative CLI commands**

Run:

```bash
PYTHONPATH=src python3 -m soinsight --help
PYTHONPATH=src python3 -m soinsight modules list
PYTHONPATH=src python3 -m soinsight modules show basic
PYTHONPATH=src python3 -m soinsight plugins list
PYTHONPATH=src python3 -m soinsight doctor
PYTHONPATH=src python3 -m soinsight basic file README.md
PYTHONPATH=src python3 -m soinsight basic elf README.md || true
```

Expected:

- Help is grouped.
- Modules list has `STATUS`.
- Modules show has capability statuses.
- Plugins list is a table.
- Doctor is grouped.
- Basic file text output has `Target`, `Analysis`, `File facts`, and `Findings` sections.
- Basic elf failure has actionable text error and exit code 3.

- [ ] **Step 2: Run full test suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Expected: all tests pass.

- [ ] **Step 3: Check docs for contradictions**

Run:

```bash
rg -n "No analyzers registered|modules list|doctor|ANALYSIS_PLAN_ERROR|10 capabilities|Registered analyzers" docs README.md
```

Update `docs/cli-reference.md` only if the text says current output lacks statuses or says there are no built-in analyzers.

- [ ] **Step 4: Commit documentation corrections if any**

If docs changed:

```bash
git add docs/cli-reference.md README.md docs/cli-output-spec.md
git commit -m "docs: align CLI reference with output spec"
```

If docs did not change, do not create an empty commit.

- [ ] **Step 5: Report final evidence**

Include:

- commit hashes created during tasks;
- full test output;
- representative command output excerpts.

---

## Self-Review

- Spec coverage: P0 is covered by Tasks 1–4. P1 is covered by Tasks 5–7. P2 is explicitly out of scope for this plan.
- Placeholder scan: no `TBD`, `TODO`, or unspecified implementation steps remain.
- Type consistency: helper names and signatures are defined before use and match later tasks.
- JSON compatibility: module, plugin, doctor, and scan JSON verification steps are included.
