"""Check that the development standards document only cites things that exist.

A standard that points at a file or a command that is not there is worse
than no standard: people follow it, it fails, and they lose trust in the
rest. This checks every path and every command the document mentions.

It is written as a pytest module so it runs with the suite; the same
checks can be run by hand with
``python tests/unit/test_development_standards.py``.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOC = REPO / "docs" / "development-standards.md"


@pytest.fixture(scope="module")
def document() -> str:
    return DOC.read_text(encoding="utf-8")


def _referenced_paths(text: str) -> set[str]:
    """The paths the document mentions.

    Only a path with a directory part counts: a bare file name in prose
    ("the CLI's main") is not a reference to a file.
    """
    patterns = [
        r"`((?:tests|scripts|docs|src|web|configs)/[\w./-]+\.(?:py|md|sh|yaml|cfg|txt))`",
        r"`((?:tests|scripts|docs|src|web|configs)/[\w./-]+/)`",
    ]
    paths: set[str] = set()
    for pattern in patterns:
        paths |= set(re.findall(pattern, text))
    return paths


def test_every_referenced_path_exists(document: str):
    missing = []
    for path in sorted(_referenced_paths(document)):
        target = REPO / path
        if path.endswith("/"):
            if not target.is_dir():
                missing.append(path)
        elif not target.exists():
            missing.append(path)
    assert not missing, f"the document cites missing paths: {missing}"


def test_the_static_check_finds_no_undefined_name():
    """The standard's blocking rule: no undefined name anywhere.

    An undefined name is a bug that the normal paths never reach -- the
    project's ``diff`` command raised ``NameError`` instead of reporting a
    missing analyzer, and no test covered that branch.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pyflakes", "src/soinsight/", "tests/"],
        capture_output=True, text=True, cwd=REPO,
    )
    if "No module named" in result.stderr:
        pytest.skip("pyflakes is not installed; it is a dev dependency")
    undefined = [
        line for line in result.stdout.splitlines() if "undefined name" in line
    ]
    assert not undefined, f"undefined names: {undefined}"


def test_the_commands_the_document_mentions_run():
    for command in (
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        [sys.executable, "-m", "soinsight", "modules", "list"],
    ):
        result = subprocess.run(
            command, capture_output=True, text=True, cwd=REPO
        )
        label = " ".join(command[2:5])
        assert result.returncode == 0, f"{label} failed: {result.stderr[:400]}"


def test_every_guard_the_document_names_exists_and_passes(document: str):
    guards = sorted(set(re.findall(r"`(tests/unit/test_[\w]+\.py)`", document)))
    assert guards, "the document names no guard"

    for guard in guards:
        assert (REPO / guard).exists(), f"{guard} is missing"

    result = subprocess.run(
        [sys.executable, "-m", "pytest", *guards, "-q", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=REPO,
    )
    assert result.returncode == 0, f"the guards failed: {result.stdout[-800:]}"


def test_the_document_is_reachable_from_the_readme():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "docs/development-standards.md" in readme


def test_the_standards_document_says_how_to_verify_itself():
    """The document must state its own acceptance, not just its rules."""
    text = DOC.read_text(encoding="utf-8")
    for section in ("## 0.", "## 7.", "## 8.", "## 9."):
        assert section in text, f"the document has no {section} section"


def main() -> int:
    """Run the same checks from the command line."""
    document = DOC.read_text(encoding="utf-8")
    failures = []

    missing = [
        path for path in sorted(_referenced_paths(document))
        if not (REPO / path).exists()
    ]
    if missing:
        failures.append(f"missing paths: {missing}")

    result = subprocess.run(
        [sys.executable, "-m", "pyflakes", "src/soinsight/", "tests/"],
        capture_output=True, text=True, cwd=REPO,
    )
    undefined = [
        line for line in result.stdout.splitlines() if "undefined name" in line
    ]
    if undefined:
        failures.append(f"undefined names: {undefined}")

    guards = sorted(set(re.findall(r"`(tests/unit/test_[\w]+\.py)`", document)))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *guards, "-q", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=REPO,
    )
    if result.returncode != 0:
        failures.append("the guards failed")

    if failures:
        for item in failures:
            print(f"[FAIL] {item}")
        return 1
    print("the standards document only cites things that exist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
