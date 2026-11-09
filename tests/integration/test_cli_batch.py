"""Integration tests for the multi-target and directory scanning paths."""

from io import StringIO
import json

import pytest

from soinsight.cli.main import main


def _write(path, blob: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


def test_scan_accepts_several_targets(tmp_path, minimal_elf64_little):
    first = _write(tmp_path / "one.so", minimal_elf64_little)
    second = _write(tmp_path / "two.so", minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(first),
            str(second),
            "--enable",
            "basic.file",
            "--format",
            "json",
        ],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["summary"]["target_count"] == 2
    assert payload["summary"]["completed_count"] == 2
    assert len(payload["results"]) == 2


def test_scan_expands_a_directory(tmp_path, minimal_elf64_little):
    _write(tmp_path / "libs" / "one.so", minimal_elf64_little)
    _write(tmp_path / "libs" / "two.so", minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(tmp_path / "libs"),
            "--enable",
            "basic.file",
            "--format",
            "json",
        ],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert payload["summary"]["target_count"] == 2


def test_include_filter_narrows_the_directory(tmp_path, minimal_elf64_little):
    _write(tmp_path / "libs" / "one.so", minimal_elf64_little)
    _write(tmp_path / "libs" / "notes.txt", b"text")
    stdout = StringIO()

    main(
        [
            "scan",
            str(tmp_path / "libs"),
            "--include",
            "*.so",
            "--enable",
            "basic.file",
            "--format",
            "json",
        ],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert payload["summary"]["target_count"] == 1


def test_exclude_filter_drops_files(tmp_path, minimal_elf64_little):
    _write(tmp_path / "libs" / "keep.so", minimal_elf64_little)
    _write(tmp_path / "libs" / "skip.so", minimal_elf64_little)
    stdout = StringIO()

    main(
        [
            "scan",
            str(tmp_path / "libs"),
            "--exclude",
            "skip*",
            "--enable",
            "basic.file",
            "--format",
            "json",
        ],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert payload["summary"]["target_count"] == 1


def test_text_output_carries_a_per_target_summary(tmp_path, minimal_elf64_little):
    _write(tmp_path / "libs" / "one.so", minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(tmp_path / "libs"),
            "--enable",
            "basic.file",
            "--format",
            "text",
        ],
        stdout=stdout,
    )

    text = stdout.getvalue()
    assert exit_code == 0
    assert "one.so" in text
    assert "汇总" in text


def test_a_single_file_behaves_as_before(tmp_path, minimal_elf64_little):
    target = _write(tmp_path / "sample.so", minimal_elf64_little)
    stdout = StringIO()

    exit_code = main(
        ["scan", str(target), "--enable", "basic.file", "--format", "json"],
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == 0
    # The single-target path keeps the original document shape.
    assert "result" in payload
    assert payload["result"]["status"] == "success"


def test_a_directory_without_matches_reports_the_error(tmp_path):
    _write(tmp_path / "libs" / "notes.txt", b"text")
    stdout = StringIO()

    exit_code = main(
        [
            "scan",
            str(tmp_path / "libs"),
            "--include",
            "*.so",
            "--enable",
            "basic.file",
            "--format",
            "json",
        ],
        stdout=stdout,
    )

    assert exit_code == 2
    payload = json.loads(stdout.getvalue())
    assert payload["diagnostics"][0]["code"] == "INVALID_TARGET"
