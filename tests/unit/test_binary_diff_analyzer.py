"""Unit tests for automation.binary-diff."""

from pathlib import Path

from soinsight.analyzers.binary_diff import AutomationBinaryDiffAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.binary_diff import diff_functions
from soinsight.infrastructure.config import RuntimeConfig


def _elf(tmp_path: Path, symbols, name: str) -> Path:
    from tests.conftest import build_elf64_with_symbols

    sample = tmp_path / name
    sample.write_bytes(build_elf64_with_symbols(symbols))
    return sample


def _analyze(config_extra: dict):
    target = AnalysisTarget(
        path=None, real_path=None, name="diff", size=0, sha256="test"
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=config_extra))
    return AutomationBinaryDiffAnalyzer().analyze(target, context)


def _write_config(tmp_path: Path, old: Path, new: Path) -> dict:
    return {
        "binary_diff": {"old_path": str(old), "new_path": str(new)},
    }


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("automation").get_capability(
        "binary-diff"
    )
    assert capability.id == AutomationBinaryDiffAnalyzer.metadata.id


def test_diff_reports_added_removed_and_moved(tmp_path):
    old = _elf(
        tmp_path,
        [
            ("kept", 1, 2, 1, 0x1000, 0x20),
            ("gone", 1, 2, 1, 0x1100, 0x10),
            ("moved", 1, 2, 1, 0x1200, 0x20),
        ],
        "old.so",
    )
    new = _elf(
        tmp_path,
        [
            ("kept", 1, 2, 1, 0x1000, 0x20),
            ("moved", 1, 2, 1, 0x1400, 0x20),
            ("added", 1, 2, 1, 0x1500, 0x30),
        ],
        "new.so",
    )

    result = _analyze(_write_config(tmp_path, old, new))

    assert result.status == AnalysisStatus.SUCCESS
    data = result.data
    assert data["added_count"] == 1
    assert data["removed_count"] == 1
    assert data["moved_count"] == 1
    by_name = {item["name"]: item for item in data["changes"]}
    assert by_name["added"]["change"] == "added"
    assert by_name["gone"]["change"] == "removed"
    assert by_name["moved"]["change"] == "moved"
    assert by_name["moved"]["old_address"] == "0x1200"
    assert by_name["moved"]["new_address"] == "0x1400"


def test_resized_only_when_the_address_is_stable(tmp_path):
    old = _elf(tmp_path, [("kept", 1, 2, 1, 0x1000, 0x20)], "old.so")
    new = _elf(tmp_path, [("kept", 1, 2, 1, 0x1000, 0x40)], "new.so")

    result = _analyze(_write_config(tmp_path, old, new))

    assert result.data["resized_count"] == 1
    change = result.data["changes"][0]
    assert change["old_size"] == 0x20
    assert change["new_size"] == 0x40


def test_identical_images_report_no_changes(tmp_path):
    old = _elf(tmp_path, [("kept", 1, 2, 1, 0x1000, 0x20)], "old.so")
    new = _elf(tmp_path, [("kept", 1, 2, 1, 0x1000, 0x20)], "new.so")

    result = _analyze(_write_config(tmp_path, old, new))

    assert result.data["change_count"] == 0
    assert "函数集无变化" in AutomationBinaryDiffAnalyzer().format_text(result)


def test_missing_side_paths_fail_with_a_diagnostic(tmp_path):
    result = _analyze({"binary_diff": {}})

    assert result.status == AnalysisStatus.FAILED
    assert [d.code for d in result.diagnostics] == ["DIFF_TARGETS_MISSING"]


def test_non_elf_target_fails_with_a_diagnostic(tmp_path):
    old = tmp_path / "old.bin"
    old.write_bytes(b"not an elf")
    new = tmp_path / "new.so"
    new.write_bytes(b"\x7fELF\x02\x01\x01")

    result = _analyze(_write_config(tmp_path, old, new))

    assert result.status == AnalysisStatus.FAILED
    assert [d.code for d in result.diagnostics] == ["DIFF_INVALID_ELF"]


def test_format_text_reports_the_summary(tmp_path):
    old = _elf(tmp_path, [("gone", 1, 2, 1, 0x1000, 0x10)], "old.so")
    new = _elf(tmp_path, [("added", 1, 2, 1, 0x1000, 0x10)], "new.so")

    result = _analyze(_write_config(tmp_path, old, new))
    text = AutomationBinaryDiffAnalyzer().format_text(result)

    assert "Binary Diff" in text
    assert "+1 新增" in text
    assert "-1 移除" in text
    assert "added" in text and "gone" in text


def test_format_text_is_none_for_a_failed_result(tmp_path):
    result = _analyze({"binary_diff": {}})
    result.status = AnalysisStatus.FAILED

    assert AutomationBinaryDiffAnalyzer().format_text(result) is None
