"""Unit tests for the target resolver's multi-target expansion."""

from pathlib import Path

import pytest

from soinsight.application.target_resolver import TargetResolutionError, TargetResolver


def _write(path: Path, blob: bytes = b"payload") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


def test_a_single_file_resolves():
    resolver = TargetResolver()
    target = resolver.resolve(_write(Path("/tmp/soinsight-resolver/a.so")))

    assert target.name == "a.so"
    assert target.size == len(b"payload")
    assert len(target.sha256) == 64


def test_a_directory_is_expanded_recursively(tmp_path):
    _write(tmp_path / "one.so")
    _write(tmp_path / "nested" / "two.so")
    _write(tmp_path / "nested" / "deep" / "three.so")

    targets = TargetResolver().resolve_many([tmp_path])

    assert sorted(item.name for item in targets) == ["one.so", "three.so", "two.so"]


def test_include_filter_keeps_only_matching_files(tmp_path):
    _write(tmp_path / "lib.so")
    _write(tmp_path / "readme.txt")

    targets = TargetResolver().resolve_many([tmp_path], include=("*.so",))

    assert [item.name for item in targets] == ["lib.so"]


def test_include_filter_matches_the_relative_path(tmp_path):
    _write(tmp_path / "libs" / "lib.so")
    _write(tmp_path / "libs" / "lib.txt")

    targets = TargetResolver().resolve_many([tmp_path], include=("libs/*.so",))

    assert [item.name for item in targets] == ["lib.so"]


def test_exclude_filter_drops_matching_files(tmp_path):
    _write(tmp_path / "lib.so")
    _write(tmp_path / "skip.so")

    targets = TargetResolver().resolve_many([tmp_path], exclude=("skip*",))

    assert [item.name for item in targets] == ["lib.so"]


def test_duplicate_files_are_reported_once(tmp_path):
    first = _write(tmp_path / "lib.so")
    alias = tmp_path / "alias.so"
    alias.symlink_to(first)

    targets = TargetResolver().resolve_many([tmp_path, first])

    assert len(targets) == 1


def test_version_control_and_cache_directories_are_skipped(tmp_path):
    _write(tmp_path / ".git" / "config")
    _write(tmp_path / "__pycache__" / "x.pyc")
    _write(tmp_path / ".venv" / "lib.so")
    _write(tmp_path / "real.so")

    targets = TargetResolver().resolve_many([tmp_path])

    assert [item.name for item in targets] == ["real.so"]


def test_a_symlink_out_of_the_tree_is_not_followed(tmp_path):
    outside = tmp_path / "outside.so"
    outside.write_bytes(b"outside")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link.so").symlink_to(outside)
    _write(tree / "real.so")

    targets = TargetResolver().resolve_many([tree])

    assert [item.name for item in targets] == ["real.so"]


def test_a_tree_of_only_external_symlinks_selects_nothing(tmp_path):
    outside = tmp_path / "outside.so"
    outside.write_bytes(b"outside")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link.so").symlink_to(outside)

    with pytest.raises(TargetResolutionError):
        TargetResolver().resolve_many([tree])


def test_a_missing_path_is_reported(tmp_path):
    with pytest.raises(TargetResolutionError):
        TargetResolver().resolve_many([tmp_path / "nope.so"])


def test_an_empty_selection_is_reported(tmp_path):
    _write(tmp_path / "readme.txt")

    with pytest.raises(TargetResolutionError):
        TargetResolver().resolve_many([tmp_path], include=("*.so",))


def test_explicit_files_also_honour_the_filters(tmp_path):
    first = _write(tmp_path / "lib.so")
    second = _write(tmp_path / "other.txt")

    targets = TargetResolver().resolve_many([first, second], include=("*.so",))

    assert [item.name for item in targets] == ["lib.so"]
