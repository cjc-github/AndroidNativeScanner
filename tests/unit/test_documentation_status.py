"""Guard tests ensuring documentation stays truthful about implementation state.

These tests fail when docs drift from the actual implementation: they must not
claim capabilities as implemented when they are still planned, and they must
reflect the current test count and real analyzers.
"""

import re
from pathlib import Path


def test_project_status_mentions_current_test_count_and_basic_file():
    text = Path("docs/project-status.md").read_text(encoding="utf-8")

    assert "basic.file" in text
    assert re.search(r"\d+ passed", text) is not None
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
