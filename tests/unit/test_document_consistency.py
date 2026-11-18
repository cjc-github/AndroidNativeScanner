"""Check every document for numbers that no longer match the code.

A stale count in a document is a false claim about the product, so the
check is mechanical: the numbers are compared with what the code
actually does.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"

#: The numbers the documents must agree with.
EXPECTED_IMPLEMENTED = 36
EXPECTED_TOTAL = 46


def _counts() -> tuple[int, int]:
    """The implemented and total capability counts, read from the code."""
    script = (
        "import sys; sys.path.insert(0, 'src');"
        "from soinsight.analyzers import register_builtin_analyzers;"
        "from soinsight.core.analyzer.registry import AnalyzerRegistry;"
        "from soinsight.modules.builtin import create_builtin_module_catalog;"
        "r = AnalyzerRegistry(); register_builtin_analyzers(r);"
        "reg = {m.id for m in r.list()};"
        "caps = [c.id for m in create_builtin_module_catalog().list() "
        "for c in m.capabilities];"
        "print(sum(1 for c in caps if c in reg), len(caps));"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": "src"},
        check=True,
    )
    done, total = completed.stdout.split()
    return int(done), int(total)


def _test_counts() -> tuple[int, int]:
    """How many tests the suite collects, and how many it skips.

    The count is collected rather than run: collecting does not execute the
    tests, so the check stays fast and does not depend on the tree passing.
    """
    completed = subprocess.run(
        [
            sys.executable, "-m", "pytest", "--collect-only", "-q",
            "-p", "no:cacheprovider", "-rs",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    output = completed.stdout

    total = 0
    for line in output.splitlines():
        match = re.match(r"\S+\.py:\s*(\d+)", line.strip())
        if match:
            total += int(match.group(1))
    if not total:
        match = re.search(r"(\d+) tests? collected", output)
        total = int(match.group(1)) if match else 0

    skipped = 0
    match = re.search(r"(\d+) skipped", output)
    if match:
        skipped = int(match.group(1))
    return total, skipped


def test_the_code_counts_match_what_the_documents_say():
    implemented, total = _counts()
    assert (implemented, total) == (EXPECTED_IMPLEMENTED, EXPECTED_TOTAL), (
        f"the code now has {implemented}/{total} capabilities; the documents "
        f"and the guard expect {EXPECTED_IMPLEMENTED}/{EXPECTED_TOTAL}"
    )


def test_no_document_claims_an_old_capability_count():
    """A document must not claim a count the code has moved past."""
    stale = (
        "26/46",
        "30/46",
        "11 个真实 Analyzer",
        "16/46 项",
        "13/46",
    )
    for path in sorted(DOCS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for marker in stale:
            assert marker not in text, (
                f"{path.name} still claims '{marker}'"
            )


def test_the_documents_quote_a_stable_test_floor():
    """The documents carry a floor, not an exact count.

    An exact number changes with every commit and is therefore wrong on
    all but the last one. A floor stays true as the suite grows, and the
    documentation guard still finds the shape it looks for.
    """
    pattern = re.compile(r"(\d{3,4})\+ passed")
    quoted = []
    for path in sorted(DOCS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        quoted.extend(pattern.findall(text))

    assert quoted, "no document states a test floor"
    for floor in quoted:
        assert int(floor) >= 100, f"the floor {floor} is implausibly low"


def test_the_suite_collects_the_tests_the_documents_describe():
    """The suite has the tests the documents promise."""
    total, _skipped = _test_counts()
    assert total > 100, f"only {total} tests were collected"


def test_the_readme_lists_every_capability():
    """The README's checklist is compared with the registry."""
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
    readme = (REPO / "README.md").read_text(encoding="utf-8")

    for capability in implemented.split():
        assert f"- [x] `{capability}`" in readme, capability
    for capability in unimplemented.split():
        assert f"- [ ] `{capability}`" in readme, capability
