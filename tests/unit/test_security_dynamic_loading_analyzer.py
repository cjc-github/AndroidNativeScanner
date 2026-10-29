"""Unit tests for the ``security.dynamic-loading`` analyzer.

The analyzer judges what ``basic.dynamic`` reports, so the tests feed it
the upstream facts directly.  That keeps every rule in isolation: a test
names one declaration and asserts on the single finding it should raise.
"""

from pathlib import Path

from soinsight.analyzers.dynamic_loading import SecurityDynamicLoadingAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Severity,
)
from soinsight.infrastructure.config import RuntimeConfig


def _dynamic_result(
    *,
    needed=("libc.so",),
    rpath=None,
    runpath=None,
    search_path=(),
    textrel=False,
    symbolic=False,
    interpose=False,
    bind_now=False,
    version_requirements=(),
    has_dynamic=True,
) -> AnalysisResult:
    """An upstream ``basic.dynamic`` result with the requested facts."""
    return AnalysisResult(
        analyzer_id="basic.dynamic",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={
            "has_dynamic": has_dynamic,
            "needed": list(needed),
            "needed_count": len(needed),
            "rpath": rpath,
            "runpath": runpath,
            "search_path": list(search_path),
            "flags": {
                "textrel": textrel,
                "symbolic": symbolic,
                "interpose": interpose,
                "bind_now": bind_now,
            },
            "symbol_versions": {
                "requirements": [
                    {"name": name, "file": file, "index": index}
                    for name, file, index in version_requirements
                ],
            },
        },
    )


def _analyze(dynamic: AnalysisResult):
    target = AnalysisTarget(
        path=Path("libsample.so"),
        real_path=Path("libsample.so"),
        name="libsample.so",
        size=1,
        sha256="test",
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra={}))
    context.add_result(dynamic)
    return SecurityDynamicLoadingAnalyzer().analyze(target, context)


def _rules(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("security").get_capability(
        "dynamic-loading"
    )
    assert SecurityDynamicLoadingAnalyzer.metadata.id == capability.id
    assert SecurityDynamicLoadingAnalyzer.metadata.requires == ("basic.dynamic",)


def test_analyzer_requires_the_upstream_dynamic_facts():
    target = AnalysisTarget(
        path=None, real_path=None, name="libsample.so", size=0, sha256="test"
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra={}))

    try:
        SecurityDynamicLoadingAnalyzer().analyze(target, context)
    except KeyError as exc:
        assert "basic.dynamic" in str(exc)
    else:  # pragma: no cover - the analyzer must not proceed without facts
        raise AssertionError("a missing upstream result must raise KeyError")


def test_rpath_is_reported_as_inherited_by_the_whole_chain():
    result = _analyze(
        _dynamic_result(rpath="/opt/lib", search_path=["/opt/lib"])
    )

    assert "security.dynamic-loading.rpath" in _rules(result)
    finding = next(
        item
        for item in result.findings
        if item.rule_id == "security.dynamic-loading.rpath"
    )
    assert finding.severity == Severity.MEDIUM


def test_runpath_alone_does_not_raise_the_rpath_rule():
    result = _analyze(
        _dynamic_result(runpath="/opt/lib", search_path=["/opt/lib"])
    )

    assert "security.dynamic-loading.rpath" not in _rules(result)


def test_relative_search_path_entry_is_reported():
    result = _analyze(
        _dynamic_result(runpath="lib", search_path=["lib", "/opt/lib"])
    )

    assert "security.dynamic-loading.relative-search-path" in _rules(result)
    assert result.data["relative_path_entries"] == ["lib"]


def test_origin_prefixed_entry_is_not_treated_as_relative():
    result = _analyze(
        _dynamic_result(
            runpath="$ORIGIN/../lib",
            search_path=["$ORIGIN/../lib", "${ORIGIN}/lib"],
        )
    )

    assert "security.dynamic-loading.relative-search-path" not in _rules(result)
    assert result.data["relative_path_entries"] == []


def test_world_writable_search_path_entry_is_reported():
    result = _analyze(
        _dynamic_result(
            runpath="/tmp:/usr/lib", search_path=["/tmp", "/usr/lib"]
        )
    )

    assert (
        "security.dynamic-loading.world-writable-search-path" in _rules(result)
    )
    assert result.data["world_writable_entries"] == ["/tmp"]


def test_read_only_search_path_is_not_reported_as_world_writable():
    result = _analyze(
        _dynamic_result(
            runpath="/usr/lib:/opt/vendor", search_path=["/usr/lib", "/opt/vendor"]
        )
    )

    assert (
        "security.dynamic-loading.world-writable-search-path" not in _rules(result)
    )
    assert result.data["world_writable_entries"] == []


def test_text_relocations_are_reported():
    result = _analyze(_dynamic_result(textrel=True))

    assert "security.dynamic-loading.textrel" in _rules(result)
    assert result.data["textrel"] is True


def test_symbolic_binding_is_reported():
    result = _analyze(_dynamic_result(symbolic=True))

    assert "security.dynamic-loading.symbolic-binding" in _rules(result)
    assert result.data["symbolic"] is True


def test_interposition_is_reported():
    result = _analyze(_dynamic_result(interpose=True))

    assert "security.dynamic-loading.interposition" in _rules(result)
    assert result.data["interpose"] is True


def test_unversioned_dependency_is_reported_only_when_other_requirements_exist():
    result = _analyze(
        _dynamic_result(
            needed=("libc.so", "libm.so"),
            version_requirements=(("GLIBC_2.17", "libc.so", 2),),
        )
    )

    assert "security.dynamic-loading.unversioned-dependency" in _rules(result)
    assert result.data["versioned_libraries"] == ["libc.so"]


def test_versioned_dependency_is_not_reported():
    result = _analyze(
        _dynamic_result(
            needed=("libc.so",),
            version_requirements=(("GLIBC_2.17", "libc.so", 2),),
        )
    )

    assert "security.dynamic-loading.unversioned-dependency" not in _rules(result)


def test_a_harmless_image_reports_no_finding():
    result = _analyze(
        _dynamic_result(
            needed=("libc.so",),
            runpath="/usr/lib",
            search_path=["/usr/lib"],
            version_requirements=(("GLIBC_2.17", "libc.so", 2),),
        )
    )

    assert result.findings == []
    assert result.data["summary"]["finding_count"] == 0
    assert result.status == AnalysisStatus.SUCCESS


def test_an_image_without_a_dynamic_section_is_diagnosed():
    result = _analyze(_dynamic_result(has_dynamic=False, needed=()))

    codes = {diagnostic.code for diagnostic in result.diagnostics}
    assert "NO_DYNAMIC_SECTION" in codes


def test_format_text_lists_the_findings():
    result = _analyze(_dynamic_result(runpath="/tmp", search_path=["/tmp"]))

    text = SecurityDynamicLoadingAnalyzer().format_text(result)

    assert text.startswith("=== 动态加载风险 ===")
    assert "libc.so" in text
    assert "=== 风险项 ===" in text
