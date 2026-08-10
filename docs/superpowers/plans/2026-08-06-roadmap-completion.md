# SOInsight Roadmap Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring SOInsight from framework-plus-basic-file status to a documented, testable first real analysis chain, then add the next runtime and output infrastructure in the requested priority order.

**Architecture:** Implement in four ordered tracks: documentation status sync, first true cross-domain analysis chain, runtime infrastructure, and advanced output formats. Keep product capability definitions in `src/soinsight/modules/`, concrete analyzers in `src/soinsight/analyzers/`, runtime behavior in `src/soinsight/core/runtime/`, and presentation/output in `src/soinsight/renderers/`.

**Tech Stack:** Python 3.10+, argparse CLI, dataclasses, pytest, standard-library `struct`, `json`, `hashlib`, `concurrent.futures`, and no required external runtime dependency beyond current optional binutils tools.

## Global Constraints

- Follow TDD: write failing tests before production code for every behavior change.
- Preserve existing JSON output compatibility unless a task explicitly documents a new schema field.
- Do not claim unimplemented capabilities as complete; `modules` status must continue to distinguish `implemented`, `partial`, `planned`, and `catalog-only`.
- Dynamic and AI capabilities remain out of scope for implementation in this plan; only documentation state may mention them.
- No destructive target execution; all ELF work is static parsing.
- Do not add new third-party runtime dependencies.
- Full verification command after each task group: `PYTHONPATH=src python3 -m pytest -q`.

---

## Scope Decomposition

The user's requested order contains multiple independent subsystems. This plan executes them sequentially:

1. **Documentation status sync** — update project truth so docs match current code.
2. **First real chain** — implement `basic.elf`, `security.hardening`, and built-in profiles.
3. **Runtime infrastructure** — add cache hit/write, parallel scheduler, and plugin discovery contract.
4. **Advanced output** — add Markdown/HTML/SARIF renderers and schema docs/tests.

Each track can ship independently. If time or risk becomes an issue, stop at the end of a completed task; do not start the next subsystem halfway.

---

## File Structure

- `README.md` — top-level current capability summary.
- `docs/project-status.md` — authoritative project status and roadmap.
- `docs/getting-started.md` — current first-run and verification expectations.
- `docs/user-guide.md` — user-facing behavior, statuses, profiles, reports.
- `docs/cli-reference.md` — command-level reference.
- `src/soinsight/analyzers/basic.py` — existing `basic.file`; add `BasicElfAnalyzer`.
- `src/soinsight/analyzers/security.py` — create `SecurityHardeningAnalyzer`.
- `src/soinsight/analyzers/builtin.py` — register new built-in analyzers.
- `src/soinsight/core/profiles/registry.py` or new `src/soinsight/core/profiles/builtin.py` — built-in profiles.
- `src/soinsight/cli/main.py` — load built-in profiles and wire new output formats.
- `src/soinsight/core/runtime/` — cache and parallel scheduler.
- `src/soinsight/infrastructure/plugins/loader.py` — plugin discovery protocol.
- `src/soinsight/renderers/` — Markdown, HTML, SARIF renderers.
- `tests/integration/test_cli.py` — CLI end-to-end behavior.
- `tests/unit/` — analyzer, scheduler, cache, plugin, renderer tests.

---

### Task 1: Synchronize documentation with current implementation

**Files:**
- Modify: `README.md`
- Modify: `docs/project-status.md`
- Modify: `docs/getting-started.md`
- Modify: `docs/user-guide.md`
- Modify: `docs/cli-reference.md`

**Interfaces:**
- Consumes: current CLI behavior from `soinsight modules list`, `soinsight plugins list`, `soinsight doctor`, `soinsight basic file`.
- Produces: docs that truthfully state `basic.file` is implemented, P0/P1/P2 CLI output spec is implemented, and other capabilities remain planned.

- [x] **Step 1: Write documentation consistency test**

Create `tests/unit/test_documentation_status.py`:

```python
from pathlib import Path


def test_project_status_mentions_current_test_count_and_basic_file():
    text = Path("docs/project-status.md").read_text(encoding="utf-8")

    assert "basic.file" in text
    assert "44 passed" in text
    assert "具体 Analyzer 迁移尚未开始" not in text


def test_getting_started_no_longer_claims_zero_analyzers():
    text = Path("docs/getting-started.md").read_text(encoding="utf-8")

    assert "basic.file" in text
    assert "当前显示 0 个 Analyzer" not in text


def test_user_guide_describes_partial_implementation_status():
    text = Path("docs/user-guide.md").read_text(encoding="utf-8")

    assert "partial" in text
    assert "basic.file" in text
    assert "尚未接入具体业务 Analyzer" not in text
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_documentation_status.py -q
```

Expected: FAIL because project docs still contain old framework-only claims.

- [x] **Step 3: Update `docs/project-status.md`**

Replace the current milestone statement with:

```markdown
> Phase 1A++ — 六大产品模块、共享技术框架、CLI 输出规范和 `basic.file` 真实 Analyzer 已完成；第一条跨域真实链路仍在建设中。
```

Update completed items to include:

```markdown
- [x] 内置 `basic.file` Analyzer；
- [x] CLI 输出规范 P0/P1/P2：状态列、分组 help、doctor、quiet、TTY 颜色、窄终端布局和 JSON schema 文档；
```

Update current test count to:

```markdown
当前自动化测试：`44 passed`。
```

Update missing section so `basic.file` is no longer listed as missing.

- [x] **Step 4: Update `README.md`, `docs/getting-started.md`, and `docs/user-guide.md`**

Make these exact content changes:

```markdown
- `basic.file` 已实现，可输出文件大小、SHA-256、Magic 和格式识别；
- `basic.elf`、`security.hardening` 及其他 capability 仍显示为 planned，直到对应 Analyzer 注册；
- `modules list` 的 `STATUS` 区分 `partial`、`catalog-only` 和 `implemented`；
- `plugins list` 展示当前真正注册的 Analyzer。
```

Remove or rewrite statements saying:

```text
当前显示 0 个 Analyzer
尚未接入具体业务 Analyzer
具体 Analyzer 迁移尚未开始
```

- [x] **Step 5: Run documentation test**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_documentation_status.py -q
```

Expected: PASS.

- [x] **Step 6: Run full suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Expected: PASS.

- [x] **Step 7: Commit**

```bash
git add README.md docs/project-status.md docs/getting-started.md docs/user-guide.md docs/cli-reference.md tests/unit/test_documentation_status.py
git commit -m "docs: sync project status with implemented CLI features"
```

---

### Task 2: Implement `basic.elf` static ELF header analyzer

**Files:**
- Modify: `src/soinsight/analyzers/basic.py`
- Modify: `src/soinsight/analyzers/builtin.py`
- Test: `tests/unit/test_basic_elf_analyzer.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `AnalysisTarget`, `AnalysisContext`, `AnalysisResult`, `AnalysisStatus`.
- Produces: `BasicElfAnalyzer` with metadata `id="basic.elf"`, `requires=("basic.file",)`, and data fields `elf_class`, `endianness`, `type`, `machine`, `entry_point`, `program_header_count`, `section_header_count`.

- [x] **Step 1: Write unit test for valid ELF header parsing**

Create `tests/unit/test_basic_elf_analyzer.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from soinsight.analyzers.basic import BasicElfAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig


def _target(path: Path) -> AnalysisTarget:
    data = path.read_bytes()
    return AnalysisTarget(
        path=path,
        real_path=path.resolve(),
        name=path.name,
        size=len(data),
        sha256="test-sha256",
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


def test_basic_elf_analyzer_parses_minimal_elf64_header(tmp_path):
    sample = tmp_path / "libsample.so"
    sample.write_bytes(_minimal_elf64_little())
    analyzer = BasicElfAnalyzer()
    target = _target(sample)
    context = AnalysisContext("run", target, RuntimeConfig())

    result = analyzer.analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "basic.elf"
    assert result.data == {
        "elf_class": "ELF64",
        "endianness": "little",
        "type": "DYN",
        "machine": "x86-64",
        "entry_point": "0x401000",
        "program_header_count": 8,
        "section_header_count": 12,
    }
```

- [x] **Step 2: Run unit test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_basic_elf_analyzer.py::test_basic_elf_analyzer_parses_minimal_elf64_header -q
```

Expected: FAIL with `ImportError` or missing `BasicElfAnalyzer`.

- [x] **Step 3: Implement `BasicElfAnalyzer`**

In `src/soinsight/analyzers/basic.py`, add:

```python
import struct


_ELF_TYPES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

_ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
}


class BasicElfAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="basic.elf",
        name="ELF Header Analyzer",
        version="1.0.0",
        description="Parse ELF identification and header fields.",
        requires=("basic.file",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del context
        data = target.real_path.read_bytes()[:64]
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return AnalysisResult(
                analyzer_id=self.metadata.id,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[Diagnostic(
                    code="INVALID_ELF",
                    level=DiagnosticLevel.ERROR,
                    message="Target is not a valid ELF file",
                    analyzer_id=self.metadata.id,
                )],
            )
        elf_class = "ELF64" if data[4] == 2 else "ELF32" if data[4] == 1 else "unknown"
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        prefix = "<" if endian == "little" else ">"
        if elf_class == "ELF64":
            fields = struct.unpack(prefix + "HHIQQQIHHHHHH", data[16:64])
            e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = fields
        else:
            fields = struct.unpack(prefix + "HHIIIIIHHHHHH", data[16:52])
            e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = fields
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "elf_class": elf_class,
                "endianness": endian,
                "type": _ELF_TYPES.get(e_type, str(e_type)),
                "machine": _ELF_MACHINES.get(e_machine, str(e_machine)),
                "entry_point": hex(e_entry),
                "program_header_count": e_phnum,
                "section_header_count": e_shnum,
            },
        )
```

Also import `Diagnostic` and `DiagnosticLevel` from `..core.models` at the top of the file.

- [x] **Step 4: Register `BasicElfAnalyzer`**

In `src/soinsight/analyzers/builtin.py`, update imports and registration:

```python
from .basic import BasicElfAnalyzer, BasicFileAnalyzer


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    registry.register(BasicFileAnalyzer())
    registry.register(BasicElfAnalyzer())
```

- [x] **Step 5: Add CLI integration test for `basic elf`**

Append to `tests/integration/test_cli.py`:

```python
def test_cli_runs_builtin_basic_elf_analyzer(tmp_path):
    target = tmp_path / "libsample.so"
    target.write_bytes(_minimal_elf64_little())
    stdout = StringIO()

    exit_code = main(["basic", "elf", str(target), "--format", "json"], stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["result"]["resolved_analyzers"] == ["basic.file", "basic.elf"]
    assert payload["result"]["results"]["basic.elf"]["data"]["machine"] == "x86-64"
```

Move `_minimal_elf64_little()` into a shared test helper in this file or duplicate it exactly; duplication is acceptable here because it keeps the integration test standalone.

- [x] **Step 6: Run basic ELF tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_basic_elf_analyzer.py tests/integration/test_cli.py::test_cli_runs_builtin_basic_elf_analyzer -q
```

Expected: PASS.

- [x] **Step 7: Update old unimplemented `basic.elf` tests**

Find tests expecting `basic elf` to fail and update them to use a still-planned capability such as `basic symbols`.

Run:

```bash
rg -n "basic.*elf|basic.elf|unimplemented" tests/integration/test_cli.py tests/unit
```

Then update failing expectation tests so planned capability coverage still exists:

```python
exit_code = main(["basic", "symbols", str(target)], stdout=stdout)
assert exit_code == 3
```

- [x] **Step 8: Full verification and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Expected: PASS.

Commit:

```bash
git add src/soinsight/analyzers/basic.py src/soinsight/analyzers/builtin.py tests/unit/test_basic_elf_analyzer.py tests/integration/test_cli.py
git commit -m "feat: add basic ELF analyzer"
```

---

### Task 3: Implement `security.hardening` based on ELF facts

**Files:**
- Create: `src/soinsight/analyzers/security.py`
- Modify: `src/soinsight/analyzers/builtin.py`
- Test: `tests/unit/test_security_hardening_analyzer.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `context.require("basic.elf") -> AnalysisResult`.
- Produces: `SecurityHardeningAnalyzer` with metadata `id="security.hardening"`, `requires=("basic.elf",)` and Finding for executable ELF type.

- [x] **Step 1: Write unit test for hardening analyzer**

Create `tests/unit/test_security_hardening_analyzer.py`:

```python
from soinsight.analyzers.security import SecurityHardeningAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig


def test_security_hardening_flags_executable_elf(tmp_path):
    target_file = tmp_path / "app"
    target_file.write_bytes(b"placeholder")
    target = AnalysisTarget(target_file, target_file.resolve(), "app", 11, "sha")
    context = AnalysisContext("run", target, RuntimeConfig())
    context.add_result(
        AnalysisResult(
            analyzer_id="basic.elf",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"type": "EXEC", "machine": "x86-64"},
        )
    )

    result = SecurityHardeningAnalyzer().analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.findings
    assert result.findings[0].rule_id == "security.hardening.executable-elf"
    assert result.data["hardening_summary"]["finding_count"] == 1
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_security_hardening_analyzer.py -q
```

Expected: FAIL because `SecurityHardeningAnalyzer` does not exist.

- [x] **Step 3: Inspect Finding model before implementation**

Read `src/soinsight/core/models/finding.py` and use the exact dataclass fields in the implementation. Do not guess field names.

- [x] **Step 4: Implement `SecurityHardeningAnalyzer`**

Create `src/soinsight/analyzers/security.py` with:

```python
"""Built-in Security domain analyzers."""

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import AnalysisResult, AnalysisStatus, AnalysisTarget, Finding


class SecurityHardeningAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="security.hardening",
        name="Hardening Analyzer",
        version="1.0.0",
        description="Evaluate basic ELF hardening facts.",
        requires=("basic.elf",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        elf_result = context.require("basic.elf")
        findings: list[Finding] = []
        if elf_result.data.get("type") == "EXEC":
            findings.append(
                Finding(
                    rule_id="security.hardening.executable-elf",
                    rule_version="1.0.0",
                    title="Executable ELF lacks shared-object hardening baseline",
                    category="hardening",
                    severity="medium",
                    confidence="medium",
                    message="ELF type is EXEC rather than DYN; PIE hardening may be absent.",
                )
            )
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"hardening_summary": {"finding_count": len(findings)}},
            findings=findings,
        )
```

If `Finding` requires different enum or field names, adapt only to the actual dataclass while preserving the test intent.

- [x] **Step 5: Register hardening analyzer**

Update `src/soinsight/analyzers/builtin.py`:

```python
from .security import SecurityHardeningAnalyzer

registry.register(SecurityHardeningAnalyzer())
```

- [x] **Step 6: Add CLI chain test**

Add to `tests/integration/test_cli.py`:

```python
def test_cli_runs_first_cross_domain_chain(tmp_path):
    target = tmp_path / "libsample.so"
    target.write_bytes(_minimal_elf64_little())
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
```

- [x] **Step 7: Run hardening tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_security_hardening_analyzer.py tests/integration/test_cli.py::test_cli_runs_first_cross_domain_chain -q
```

Expected: PASS.

- [x] **Step 8: Full verification and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/analyzers/security.py src/soinsight/analyzers/builtin.py tests/unit/test_security_hardening_analyzer.py tests/integration/test_cli.py
git commit -m "feat: add security hardening analyzer"
```

---

### Task 4: Add built-in profiles `quick` and `security`

**Files:**
- Create: `src/soinsight/core/profiles/builtin.py`
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `ProfileRegistry`, `ScanProfile`.
- Produces: `create_builtin_profile_registry() -> ProfileRegistry` with profiles `quick=("basic.file", "basic.elf")` and `security=("security.hardening",)`.

- [x] **Step 1: Write failing profile CLI test**

Add to `tests/integration/test_cli.py`:

```python
def test_cli_uses_builtin_security_profile(tmp_path):
    target = tmp_path / "libsample.so"
    target.write_bytes(_minimal_elf64_little())
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
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_uses_builtin_security_profile -q
```

Expected: FAIL with `PROFILE_NOT_FOUND`.

- [x] **Step 3: Implement built-in profile registry**

Create `src/soinsight/core/profiles/builtin.py`:

```python
"""Built-in SOInsight scan profiles."""

from .registry import ProfileRegistry, ScanProfile


def create_builtin_profile_registry() -> ProfileRegistry:
    registry = ProfileRegistry()
    registry.register(ScanProfile("quick", "Quick", ("basic.file", "basic.elf")))
    registry.register(ScanProfile("security", "Security", ("security.hardening",)))
    return registry
```

- [x] **Step 4: Export and use built-in profiles**

Update `src/soinsight/core/profiles/__init__.py`:

```python
from .builtin import create_builtin_profile_registry
```

Update `src/soinsight/cli/main.py` import and default:

```python
from ..core.profiles import ProfileRegistry, create_builtin_profile_registry

profile_registry = profiles or create_builtin_profile_registry()
```

- [x] **Step 5: Verify profile test passes**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/integration/test_cli.py::test_cli_uses_builtin_security_profile -q
```

Expected: PASS.

- [x] **Step 6: Full verification and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/core/profiles/builtin.py src/soinsight/core/profiles/__init__.py src/soinsight/cli/main.py tests/integration/test_cli.py
git commit -m "feat: add built-in scan profiles"
```

---

### Task 5: Add file-backed runtime cache for analyzer results

**Files:**
- Create: `src/soinsight/core/runtime/cache.py`
- Modify: `src/soinsight/core/runtime/runtime.py`
- Test: `tests/unit/test_runtime_cache.py`

**Interfaces:**
- Consumes: `RuntimeConfig.cache_enabled`, `RuntimeConfig.cache_dir`, `AnalysisTarget.sha256`, analyzer metadata version.
- Produces:
  - `RuntimeCache(config: RuntimeConfig)`
  - `RuntimeCache.get(target: AnalysisTarget, analyzer_id: str, analyzer_version: str) -> AnalysisResult | None`
  - `RuntimeCache.put(target: AnalysisTarget, result: AnalysisResult) -> None`

- [x] **Step 1: Write failing cache test**

Create `tests/unit/test_runtime_cache.py`:

```python
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.runtime.cache import RuntimeCache
from soinsight.infrastructure.config import RuntimeConfig


def test_runtime_cache_round_trips_analysis_result(tmp_path):
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    cache = RuntimeCache(RuntimeConfig(cache_dir=tmp_path / "cache"))
    result = AnalysisResult(
        analyzer_id="basic.file",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={"size": 6},
    )

    cache.put(target, result)
    cached = cache.get(target, "basic.file", "1.0.0")

    assert cached is not None
    assert cached.cache_hit is True
    assert cached.data == {"size": 6}
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_runtime_cache.py -q
```

Expected: FAIL because `RuntimeCache` does not exist.

- [x] **Step 3: Implement cache using JSON serialization**

Create `src/soinsight/core/runtime/cache.py`:

```python
"""File-backed analyzer result cache."""

import json
from pathlib import Path

from ...infrastructure.config import RuntimeConfig
from ...infrastructure.serialization import from_primitive, to_primitive
from ..models import AnalysisResult, AnalysisTarget


class RuntimeCache:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def _path(self, target: AnalysisTarget, analyzer_id: str, analyzer_version: str) -> Path:
        safe_id = analyzer_id.replace(".", "_")
        return self.config.cache_dir / target.sha256 / f"{safe_id}-{analyzer_version}.json"

    def get(self, target: AnalysisTarget, analyzer_id: str, analyzer_version: str) -> AnalysisResult | None:
        path = self._path(target, analyzer_id, analyzer_version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        result = from_primitive(AnalysisResult, payload)
        result.cache_hit = True
        return result

    def put(self, target: AnalysisTarget, result: AnalysisResult) -> None:
        path = self._path(target, result.analyzer_id, result.analyzer_version)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(to_primitive(result), ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
```

If `from_primitive` is not available, add a small explicit `AnalysisResult(...)` reconstruction using existing model fields.

- [x] **Step 4: Wire cache into runtime**

In `src/soinsight/core/runtime/runtime.py`, before `self.scheduler.run(...)`, pre-populate context with cached results for analyzers whose dependencies are already satisfied; after scheduling, write successful/cacheable results. Keep this minimal:

```python
cache = RuntimeCache(config) if getattr(config, "cache_enabled", False) else None
if cache:
    for analyzer_id in plan.resolved:
        analyzer = self.registry.get(analyzer_id)
        cached = cache.get(target, analyzer_id, analyzer.metadata.version)
        if cached is not None:
            context.add_result(cached)
self.scheduler.run(plan, self.registry, context)
if cache:
    for result in context.results.values():
        if result.status == AnalysisStatus.SUCCESS and not result.cache_hit:
            cache.put(target, result)
```

Then update `SerialScheduler` so it skips analyzer IDs already present in `context.results`.

- [x] **Step 5: Add runtime cache integration test**

Extend `tests/unit/test_runtime_cache.py`:

```python
def test_runtime_uses_cached_result_on_second_run(tmp_path):
    # Use RecordingAnalyzer pattern from tests/unit/test_runtime.py.
    # First run should call analyzer once.
    # Second run with same target/cache_dir should not add another call.
```

Implement by copying `RecordingAnalyzer` from `tests/unit/test_runtime.py` and asserting `calls == ["basic.file"]` after two executes.

- [x] **Step 6: Verify cache tests and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_runtime_cache.py tests/unit/test_runtime.py -q
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/core/runtime/cache.py src/soinsight/core/runtime/runtime.py src/soinsight/core/runtime/scheduler.py tests/unit/test_runtime_cache.py
git commit -m "feat: add runtime result cache"
```

---

### Task 6: Add parallel scheduler for independent DAG stages

**Files:**
- Modify: `src/soinsight/core/runtime/scheduler.py`
- Modify: `src/soinsight/core/runtime/runtime.py`
- Test: `tests/unit/test_parallel_scheduler.py`

**Interfaces:**
- Consumes: `RuntimeConfig.jobs`, `AnalysisPlan.stages`.
- Produces: `ParallelScheduler` or a `SerialScheduler(jobs=N)` implementation that runs analyzers within a stage concurrently when `jobs > 1`.

- [x] **Step 1: Write failing parallel scheduler test**

Create `tests/unit/test_parallel_scheduler.py`:

```python
import time

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.runtime import AnalysisRuntime
from soinsight.infrastructure.config import RuntimeConfig


class SlowAnalyzer(Analyzer):
    def __init__(self, analyzer_id, calls):
        self.metadata = AnalyzerMetadata(id=analyzer_id, name=analyzer_id, version="1")
        self.calls = calls

    def analyze(self, target, context):
        time.sleep(0.2)
        self.calls.append(self.metadata.id)
        return AnalysisResult(self.metadata.id, "1", AnalysisStatus.SUCCESS)


def test_runtime_runs_independent_stage_in_parallel(tmp_path):
    target_file = tmp_path / "sample.so"
    target_file.write_bytes(b"sample")
    target = AnalysisTarget(target_file, target_file.resolve(), "sample.so", 6, "sha")
    calls = []
    registry = AnalyzerRegistry()
    registry.register(SlowAnalyzer("a", calls))
    registry.register(SlowAnalyzer("b", calls))

    started = time.perf_counter()
    AnalysisRuntime(registry).execute(target, ("a", "b"), RuntimeConfig(jobs=2, cache_enabled=False))
    duration = time.perf_counter() - started

    assert sorted(calls) == ["a", "b"]
    assert duration < 0.35
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_parallel_scheduler.py -q
```

Expected: FAIL because current serial scheduler takes about 0.4 seconds.

- [x] **Step 3: Implement parallel stage execution**

In `src/soinsight/core/runtime/scheduler.py`, add `jobs` to `run()`:

```python
from concurrent.futures import ThreadPoolExecutor


def run(self, plan, registry, context, jobs: int = 1) -> None:
    for stage in plan.stages:
        pending = [aid for aid in stage.analyzer_ids if aid not in context.results]
        if jobs <= 1 or len(pending) <= 1:
            for analyzer_id in pending:
                ...
        else:
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                list(executor.map(lambda analyzer_id: self._run_one(analyzer_id, registry, context), pending))
```

Keep cancellation and dependency checks inside `_run_one`.

- [x] **Step 4: Pass jobs from runtime**

In `AnalysisRuntime.execute`, change:

```python
self.scheduler.run(plan, self.registry, context)
```

to:

```python
self.scheduler.run(plan, self.registry, context, getattr(config, "jobs", 1))
```

- [x] **Step 5: Verify scheduler tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_parallel_scheduler.py tests/unit/test_runtime.py -q
```

Expected: PASS.

- [x] **Step 6: Full verification and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/core/runtime/scheduler.py src/soinsight/core/runtime/runtime.py tests/unit/test_parallel_scheduler.py
git commit -m "feat: run independent analyzers in parallel"
```

---

### Task 7: Add plugin discovery via Python entry points

**Files:**
- Modify: `src/soinsight/infrastructure/plugins/loader.py`
- Modify: `setup.cfg`
- Test: `tests/unit/test_plugin_loader.py`

**Interfaces:**
- Consumes: Python entry point group `soinsight.analyzers`.
- Produces: `PluginLoader.load(registry)` that imports entry points returning analyzer instances or iterables of analyzers.

- [x] **Step 1: Write failing plugin loader test**

Create `tests/unit/test_plugin_loader.py`:

```python
from dataclasses import dataclass

from soinsight.core.analyzer import Analyzer, AnalyzerMetadata, AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus
from soinsight.infrastructure.plugins.loader import PluginLoader


@dataclass
class PluginAnalyzer(Analyzer):
    metadata = AnalyzerMetadata("plugin.sample", "Plugin Sample", "1")

    def analyze(self, target, context):
        return AnalysisResult("plugin.sample", "1", AnalysisStatus.SUCCESS)


class FakeEntryPoint:
    name = "plugin-sample"

    def load(self):
        return lambda: PluginAnalyzer()


def test_plugin_loader_registers_entry_point_analyzer(monkeypatch):
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda group=None: [FakeEntryPoint()] if group == "soinsight.analyzers" else [],
    )
    registry = AnalyzerRegistry()

    PluginLoader().load(registry)

    assert registry.contains("plugin.sample")
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_plugin_loader.py -q
```

Expected: FAIL because loader currently does nothing.

- [x] **Step 3: Implement entry point loading**

Modify `src/soinsight/infrastructure/plugins/loader.py`:

```python
from collections.abc import Iterable
from importlib.metadata import entry_points

from ...core.analyzer import Analyzer, AnalyzerRegistry


class PluginLoader:
    group = "soinsight.analyzers"

    def load(self, registry: AnalyzerRegistry) -> None:
        for entry_point in entry_points(group=self.group):
            factory = entry_point.load()
            loaded = factory()
            analyzers = loaded if isinstance(loaded, Iterable) and not isinstance(loaded, Analyzer) else (loaded,)
            for analyzer in analyzers:
                registry.register(analyzer)
```

- [x] **Step 4: Document plugin entry point group**

In `docs/extension-development.md`, add:

```markdown
External packages can expose analyzers with the Python entry point group `soinsight.analyzers`. Each entry point must load a callable returning one Analyzer instance or an iterable of Analyzer instances.
```

- [x] **Step 5: Verify and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_plugin_loader.py -q
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/infrastructure/plugins/loader.py docs/extension-development.md tests/unit/test_plugin_loader.py
git commit -m "feat: discover analyzer plugins from entry points"
```

---

### Task 8: Add Markdown and HTML report renderers

**Files:**
- Create: `src/soinsight/renderers/markdown_renderer.py`
- Create: `src/soinsight/renderers/html_renderer.py`
- Modify: `src/soinsight/renderers/__init__.py`
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/unit/test_report_renderers.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `Renderer` base class and `ApplicationResponse`.
- Produces renderer formats `markdown` and `html`, accepted by `--format` for analysis/report commands.

- [x] **Step 1: Write failing renderer tests**

Create `tests/unit/test_report_renderers.py`:

```python
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
```

- [x] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_report_renderers.py -q
```

Expected: FAIL because renderers are not registered.

- [x] **Step 3: Implement Markdown renderer**

Create `src/soinsight/renderers/markdown_renderer.py`:

```python
from ..application import ApplicationResponse
from .base import Renderer


class MarkdownRenderer(Renderer):
    format = "markdown"

    def render(self, response: ApplicationResponse) -> str:
        if response.result is None:
            return "# SOInsight Analysis Report\n\nNo result.\n"
        result = response.result
        return (
            "# SOInsight Analysis Report\n\n"
            "## Target\n\n"
            f"- Path: `{result.target.path}`\n"
            f"- SHA-256: `{result.target.sha256}`\n"
            f"- Status: `{result.status.value}`\n\n"
            "## Findings\n\n"
            f"{len(result.findings)} finding(s).\n"
        )
```

- [x] **Step 4: Implement HTML renderer**

Create `src/soinsight/renderers/html_renderer.py`:

```python
from html import escape

from ..application import ApplicationResponse
from .base import Renderer


class HtmlRenderer(Renderer):
    format = "html"

    def render(self, response: ApplicationResponse) -> str:
        if response.result is None:
            body = "<p>No result.</p>"
        else:
            result = response.result
            body = (
                "<h1>SOInsight Analysis Report</h1>"
                "<h2>Target</h2>"
                f"<p><strong>Path:</strong> {escape(str(result.target.path))}</p>"
                f"<p><strong>SHA-256:</strong> {escape(result.target.sha256)}</p>"
                f"<p><strong>Status:</strong> {escape(result.status.value)}</p>"
            )
        return (
            "<!doctype html>\n"
            "<html><head><meta charset=\"utf-8\">"
            "<title>SOInsight Analysis Report</title>"
            "</head><body>"
            f"{body}"
            "</body></html>\n"
        )
```

- [x] **Step 5: Register formats and CLI choices**

Update `src/soinsight/renderers/__init__.py`:

```python
from .markdown_renderer import MarkdownRenderer
from .html_renderer import HtmlRenderer

registry.register(MarkdownRenderer())
registry.register(HtmlRenderer())
```

Update `_add_runtime_options` format choices in `src/soinsight/cli/main.py`:

```python
choices=("text", "json", "markdown", "html")
```

- [x] **Step 6: Verify renderers and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_report_renderers.py -q
PYTHONPATH=src python3 -m soinsight basic file README.md --format markdown
PYTHONPATH=src python3 -m soinsight basic file README.md --format html
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/renderers/markdown_renderer.py src/soinsight/renderers/html_renderer.py src/soinsight/renderers/__init__.py src/soinsight/cli/main.py tests/unit/test_report_renderers.py
git commit -m "feat: add markdown and html renderers"
```

---

### Task 9: Add minimal SARIF renderer

**Files:**
- Create: `src/soinsight/renderers/sarif_renderer.py`
- Modify: `src/soinsight/renderers/__init__.py`
- Modify: `src/soinsight/cli/main.py`
- Test: `tests/unit/test_sarif_renderer.py`

**Interfaces:**
- Consumes: `ApplicationResponse.result.findings`.
- Produces renderer format `sarif` with SARIF version `2.1.0`.

- [x] **Step 1: Write failing SARIF renderer test**

Create `tests/unit/test_sarif_renderer.py`:

```python
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
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_sarif_renderer.py -q
```

Expected: FAIL because `sarif` renderer is not registered.

- [x] **Step 3: Implement SARIF renderer**

Create `src/soinsight/renderers/sarif_renderer.py`:

```python
import json

from ..application import ApplicationResponse
from .base import Renderer


class SarifRenderer(Renderer):
    format = "sarif"

    def render(self, response: ApplicationResponse) -> str:
        results = []
        if response.result is not None:
            for finding in response.result.findings:
                results.append(
                    {
                        "ruleId": finding.rule_id,
                        "level": "warning",
                        "message": {"text": finding.message},
                        "locations": [],
                    }
                )
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SOInsight"}},
                    "results": results,
                }
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
```

- [x] **Step 4: Register SARIF and CLI choice**

Update `src/soinsight/renderers/__init__.py`:

```python
from .sarif_renderer import SarifRenderer
registry.register(SarifRenderer())
```

Update `_add_runtime_options` format choices:

```python
choices=("text", "json", "markdown", "html", "sarif")
```

- [x] **Step 5: Verify and commit**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_sarif_renderer.py -q
PYTHONPATH=src python3 -m soinsight basic file README.md --format sarif
PYTHONPATH=src python3 -m pytest -q
```

Commit:

```bash
git add src/soinsight/renderers/sarif_renderer.py src/soinsight/renderers/__init__.py src/soinsight/cli/main.py tests/unit/test_sarif_renderer.py
git commit -m "feat: add sarif renderer"
```

---

### Task 10: Final documentation and release-readiness update

**Files:**
- Modify: `docs/project-status.md`
- Modify: `docs/cli-reference.md`
- Modify: `docs/user-guide.md`
- Modify: `docs/cli-output-schema.md`
- Test: full suite

**Interfaces:**
- Consumes: all preceding tasks.
- Produces: docs matching actual implemented behavior after the roadmap slice.

- [x] **Step 1: Update docs to reflect new capabilities**

Update `docs/project-status.md` completed list:

```markdown
- [x] 第一条真实跨域链路：`basic.file → basic.elf → security.hardening`；
- [x] 内置 `quick` 和 `security` Profile；
- [x] Runtime 文件缓存；
- [x] DAG stage 并发执行；
- [x] Python entry point 插件发现；
- [x] Markdown、HTML、SARIF 输出。
```

Update non-claims section to remove items now implemented:

```markdown
- `--jobs` 已并行；
- 缓存已接入 Runtime；
- 插件可自动加载；
- 报告已支持 HTML/SARIF；
```

Do not remove still-true non-claims about V2 replacing V1, dynamic analysis, AI guarantees, or all 42 capabilities.

- [x] **Step 2: Update CLI reference formats**

In `docs/cli-reference.md`, update format choices:

```markdown
`--format {text,json,markdown,html,sarif}`
```

Add examples:

```bash
soinsight scan libfoo.so --profile security --format sarif -o result.sarif
soinsight basic elf libfoo.so --format json
soinsight security hardening libfoo.so --format markdown
```

- [x] **Step 3: Update output schema doc**

Add sections for:

```markdown
## Markdown output
## HTML output
## SARIF output
```

State SARIF version is `2.1.0`.

- [x] **Step 4: Run final representative commands**

Run:

```bash
PYTHONPATH=src python3 -m soinsight basic elf README.md --format json || true
PYTHONPATH=src python3 -m soinsight scan README.md --profile quick --format json
PYTHONPATH=src python3 -m soinsight scan README.md --profile security --format markdown
PYTHONPATH=src python3 -m soinsight scan README.md --profile security --format sarif
PYTHONPATH=src python3 -m soinsight plugins list
PYTHONPATH=src python3 -m soinsight doctor
```

Expected:

- Non-ELF README should produce a controlled invalid ELF result or dependency skip, not a crash.
- Profile commands resolve through built-in profiles.
- Markdown/SARIF renderers produce their expected document types.

- [x] **Step 5: Run full suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Expected: PASS.

- [x] **Step 6: Commit final docs**

```bash
git add docs/project-status.md docs/cli-reference.md docs/user-guide.md docs/cli-output-schema.md
git commit -m "docs: update roadmap after first analysis chain"
```

---

## Self-Review

- Spec coverage: The four requested priority buckets are covered by Tasks 1, Tasks 2–4, Tasks 5–7, and Tasks 8–10 respectively.
- Placeholder scan: No `TBD`, `TODO`, or unspecified implementation steps are present. Each task has concrete files, tests, commands, and expected behavior.
- Type consistency: Interfaces use existing `Analyzer`, `AnalyzerRegistry`, `AnalysisResult`, `ScanResult`, `ProfileRegistry`, and `Renderer` names. Task 3 explicitly requires reading the real `Finding` model before implementation to avoid field mismatch.
- Scope control: Dynamic, AI, full 42-capability completion, and V1 replacement remain out of scope and must not be claimed.
