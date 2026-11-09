"""Guard the README's capability checklist against the real registry.

The README lists every capability with a checkbox. A stale checkbox is a
false claim about the product, so this test compares the list with the
registry instead of trusting a hand-maintained count.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"


def _registered_capabilities() -> tuple[set[str], set[str]]:
    """The capability ids that have an analyzer, and those that do not."""
    script = (
        "import sys; sys.path.insert(0, 'src');"
        "from soinsight.analyzers import register_builtin_analyzers;"
        "from soinsight.core.analyzer.registry import AnalyzerRegistry;"
        "from soinsight.modules.builtin import create_builtin_module_catalog;"
        "r = AnalyzerRegistry(); register_builtin_analyzers(r);"
        "reg = {m.id for m in r.list()};"
        "caps = [c.id for m in create_builtin_module_catalog().list() "
        "for c in m.capabilities];"
        "print('\\n'.join(c for c in caps if c in reg));"
        "print('---');"
        "print('\\n'.join(c for c in caps if c not in reg));"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=True,
    )
    implemented, _, unimplemented = completed.stdout.partition("---\n")
    return set(implemented.split()), set(unimplemented.split())


def test_readme_lists_every_capability_with_the_right_checkbox():
    implemented, unimplemented = _registered_capabilities()
    text = README.read_text(encoding="utf-8")

    assert len(implemented) + len(unimplemented) == 46

    for capability in implemented:
        assert f"- [x] `{capability}`" in text, (
            f"{capability} 已实现但 README 未勾选"
        )
    for capability in unimplemented:
        assert f"- [ ] `{capability}`" in text, (
            f"{capability} 未实现但 README 未列出"
        )


def test_readme_does_not_check_an_unimplemented_capability():
    implemented, _ = _registered_capabilities()
    text = README.read_text(encoding="utf-8")

    for line in text.splitlines():
        match = re.match(r"- \[x\] `([^`]+)`", line)
        if match is None:
            continue
        assert match.group(1) in implemented, (
            f"README 勾选了未实现的能力: {match.group(1)}"
        )


def test_the_summary_table_adds_up():
    text = README.read_text(encoding="utf-8")

    rows = re.findall(
        r"\| (?:基础分析|高级分析|安全分析|动态分析|AI 分析|自动化) `?\w+`? \| (\d+) \| ✅ (\d+) \|",
        text,
    )
    assert rows, "the summary table is missing"

    total = sum(int(count) for count, _ in rows)
    done = sum(int(count) for _, count in rows)

    assert total == 46
    assert done == 36


def test_the_header_snapshot_matches_the_table():
    text = README.read_text(encoding="utf-8")

    assert "已实现 36/46" in text
    for stale in ("已实现 30/46", "16/46"):
        assert stale not in text, f"README 仍含过期数字: {stale}"
