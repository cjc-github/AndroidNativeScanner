"""Unit tests for the taint function library."""

import pytest

from soinsight.infrastructure.taint_library import (
    TaintLibraryError,
    load_taint_library,
    parse_taint_library,
)


def _library(**sections):
    payload = {"version": 1}
    payload.update(sections)
    return parse_taint_library(payload)


def test_the_builtin_library_loads():
    library = load_taint_library("configs/taint-functions.yaml")

    assert not library.is_empty
    assert library.sources
    assert library.sinks
    assert library.propagators


def test_the_builtin_library_knows_the_usual_functions():
    library = load_taint_library("configs/taint-functions.yaml")

    assert library.find_source("recv").name == "recv"
    assert library.find_source("getenv").name == "getenv"
    assert library.find_sink("system").name == "system"
    assert library.find_sink("printf").name == "printf"


def test_a_function_that_is_not_in_the_table_does_not_match():
    library = load_taint_library("configs/taint-functions.yaml")

    assert library.find_source("my_own_helper") is None
    assert library.find_sink("my_own_helper") is None


def test_the_pattern_is_anchored_to_the_whole_name():
    """``read`` must not match ``read_record``."""
    library = _library(
        sources=[{"name": "read", "match": "^read($|@)", "kind": "return"}],
    )

    assert library.find_source("read") is not None
    assert library.find_source("read_record") is None


def test_a_demangled_name_is_used_when_asked():
    library = _library(
        sources=[
            {
                "name": "fancy",
                "match": "Parser::parse",
                "kind": "return",
                "match_demangled": True,
            }
        ],
    )

    assert library.find_source("_ZN5Parser5parseEPKc", "Parser::parse(char const*)")
    assert library.find_source("_ZN5Parser5parseEPKc") is None


def test_the_argument_kind_carries_the_index():
    library = _library(
        sinks=[
            {
                "name": "sink",
                "match": "^sink$",
                "kind": "argument",
                "argument": 2,
            }
        ],
    )

    sink = library.find_sink("sink")
    assert sink.argument == 2
    assert sink.kind == "argument"


def test_an_entry_without_a_name_is_rejected():
    with pytest.raises(TaintLibraryError):
        _library(sinks=[{"match": "^x$"}])


def test_an_unknown_kind_is_rejected():
    with pytest.raises(TaintLibraryError):
        _library(sinks=[{"name": "x", "match": "^x$", "kind": "sideways"}])


def test_a_negative_argument_is_rejected():
    with pytest.raises(TaintLibraryError):
        _library(sinks=[{"name": "x", "match": "^x$", "argument": -1}])


def test_an_unsupported_version_is_rejected():
    with pytest.raises(TaintLibraryError):
        parse_taint_library({"version": 2})


def test_a_missing_file_is_reported():
    with pytest.raises(TaintLibraryError):
        load_taint_library("configs/does-not-exist.yaml")


def test_a_malformed_file_is_reported(tmp_path):
    broken = tmp_path / "broken.yaml"
    broken.write_text("sources: [\n  - name: unterminated\n", encoding="utf-8")

    with pytest.raises(TaintLibraryError):
        load_taint_library(broken)


def test_an_empty_library_is_allowed(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("version: 1\n", encoding="utf-8")

    library = load_taint_library(empty)

    assert library.is_empty


def test_the_library_serializes_for_the_report():
    library = _library(
        sources=[{"name": "s", "match": "^s$", "kind": "return"}],
        sinks=[{"name": "k", "match": "^k$"}],
    )

    payload = library.as_dict()

    assert payload["source_count"] == 1
    assert payload["sink_count"] == 1
    assert payload["sources"][0]["name"] == "s"
