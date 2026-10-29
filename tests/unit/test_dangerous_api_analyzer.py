"""Unit tests for the dangerous API analyzer."""

import pytest

from soinsight.analyzers.security import (
    DANGEROUS_APIS,
    SecurityDangerousApiAnalyzer,
    _canonical_symbol,
)
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Severity,
)
from soinsight.infrastructure.config import RuntimeConfig


def _symbols_result(data: dict) -> AnalysisResult:
    return AnalysisResult(
        analyzer_id="basic.symbols",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data=data,
    )


def _context(symbols_data: dict, **extra) -> AnalysisContext:
    target = AnalysisTarget(
        path=None, real_path=None, name="libsample.so", size=0, sha256="test"
    )
    context = AnalysisContext("run", target, RuntimeConfig(extra=extra))
    context.add_result(_symbols_result(symbols_data))
    return context


def _analyze(symbols_data: dict, **extra):
    return SecurityDangerousApiAnalyzer().analyze(None, _context(symbols_data, **extra))


def _callgraph_result(records: list[dict]) -> AnalysisResult:
    return AnalysisResult(
        analyzer_id="basic.callgraph",
        analyzer_version="1.0.0",
        status=AnalysisStatus.SUCCESS,
        data={"external_calls": records},
    )


def _analyze_with_callgraph(symbols_data: dict, records: list[dict]):
    context = _context(symbols_data)
    context.add_result(_callgraph_result(records))
    return SecurityDangerousApiAnalyzer().analyze(None, context)


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("security").get_capability(
        "dangerous-api"
    )
    assert SecurityDangerousApiAnalyzer.metadata.id == capability.id
    assert SecurityDangerousApiAnalyzer.metadata.requires == ("basic.symbols",)


def test_analyzer_flags_dangerous_imports():
    data = {
        "imports": [
            {"name": "system", "source": ".dynsym"},
            {"name": "strcpy", "source": ".dynsym"},
            {"name": "memcpy", "source": ".dynsym"},   # deliberately not a rule
        ],
        "functions": [],
        "stripped": False,
    }

    result = _analyze(data)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.analyzer_id == "security.dangerous-api"
    assert result.data["matched_apis"] == ["strcpy", "system"]
    assert result.data["counts_by_severity"] == {"critical": 1, "high": 1}

    finding = result.findings[0]
    assert finding.rule_id == "security.dangerous-api.system"
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.HIGH
    assert finding.category == "dangerous-api"
    assert finding.evidence[0]["usage"] == "import"
    assert finding.remediation


def test_analyzer_flags_dangerous_exports():
    data = {
        "imports": [],
        "functions": [{"name": "Java_com_example_runCmd", "source": ".dynsym"}],
        "stripped": False,
    }

    result = _analyze(data)

    # A symbol name that merely contains a keyword must not match.
    assert result.data["finding_count"] == 0
    assert result.findings == []


def test_analyzer_flags_exported_dangerous_wrapper():
    data = {
        "imports": [],
        "functions": [{"name": "dlopen", "source": ".dynsym"}],
        "stripped": False,
    }

    result = _analyze(data)

    assert result.data["matched_apis"] == ["dlopen"]
    assert result.findings[0].evidence[0]["usage"] == "export"


def test_analyzer_normalises_fortify_variants():
    data = {
        "imports": [
            {"name": "__strcpy_chk", "source": ".dynsym"},
            {"name": "__memcpy_chk", "source": ".dynsym"},
        ],
        "functions": [],
        "stripped": False,
    }

    result = _analyze(data)

    assert result.data["matched_apis"] == ["strcpy"]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("system", "system"),
        ("__strcpy_chk", "strcpy"),
        ("__isoc99_sscanf", "isoc99_sscanf"),
        ("___hidden", "___hidden"),
        ("dlopen", "dlopen"),
        ("_chk", "_chk"),  # nothing left to keep; not a FORTIFY suffix
    ],
)
def test_canonical_symbol(name, expected):
    assert _canonical_symbol(name) == expected


def test_analyzer_respects_min_severity():
    data = {
        "imports": [
            {"name": "system", "source": ".dynsym"},     # critical
            {"name": "socket", "source": ".dynsym"},     # low
        ],
        "functions": [],
        "stripped": False,
    }
    options = {"capability_options": {"security.dangerous-api": {"min_severity": "high"}}}

    result = _analyze(data, **options)

    assert result.data["matched_apis"] == ["system"]


def test_analyzer_can_disable_imports_or_exports():
    data = {
        "imports": [{"name": "system", "source": ".dynsym"}],
        "functions": [{"name": "popen", "source": ".dynsym"}],
        "stripped": False,
    }
    options = {
        "capability_options": {
            "security.dangerous-api": {
                "include_imports": False,
                "include_exports": False,
            }
        }
    }

    result = _analyze(data, **options)

    assert result.data["finding_count"] == 0


def test_analyzer_ignores_unknown_min_severity():
    data = {"imports": [{"name": "system", "source": ".dynsym"}], "functions": []}
    options = {
        "capability_options": {"security.dangerous-api": {"min_severity": "bogus"}}
    }

    result = _analyze(data, **options)

    # An unusable value falls back to the default rather than dropping output.
    assert result.data["finding_count"] == 1


def test_analyzer_notes_stripped_symbol_table():
    data = {
        "imports": [{"name": "system", "source": ".dynsym"}],
        "functions": [],
        "stripped": True,
    }

    result = _analyze(data)

    codes = [diagnostic.code for diagnostic in result.diagnostics]
    assert codes == ["SYMBOLS_STRIPPED"]


def test_analyzer_handles_empty_symbol_result():
    result = _analyze({"imports": [], "functions": [], "stripped": False})

    assert result.status == AnalysisStatus.SUCCESS
    assert result.data == {
        "matched_apis": [],
        "finding_count": 0,
        "counts_by_severity": {},
        "call_site_evidence": False,
        "call_site_confirmed_apis": [],
        "call_site_confirmed_count": 0,
    }
    assert result.diagnostics == []


def test_analyzer_result_is_json_serializable():
    import json

    data = {
        "imports": [{"name": "system", "source": ".dynsym"}],
        "functions": [],
        "stripped": False,
    }

    payload = json.dumps(_analyze(data).data)
    assert "system" in payload


def test_rule_table_entries_are_well_formed():
    for name, (category, severity, remediation) in DANGEROUS_APIS.items():
        assert name and name == name.lower(), name
        assert isinstance(severity, Severity), name
        assert category and remediation, name


def test_rule_table_excludes_ubiquitous_primitives():
    """memcpy/malloc/printf appear everywhere and must not be reported."""
    for noisy in ("memcpy", "memmove", "memset", "malloc", "free", "printf"):
        assert noisy not in DANGEROUS_APIS


def test_analyzer_is_registered_as_default_enabled():
    assert SecurityDangerousApiAnalyzer.metadata.default_enabled is True
    assert SecurityDangerousApiAnalyzer.metadata.kind.value == "detector"


def test_import_finding_carries_call_sites_when_callgraph_is_present():
    symbols = {
        "imports": [{"name": "system", "source": ".dynsym"}],
        "functions": [],
        "stripped": False,
    }
    records = [
        {
            "name": "system",
            "plt_address": "0x1020",
            "call_site_count": 2,
            "call_sites": ["0x1100", "0x1200"],
        }
    ]

    result = _analyze_with_callgraph(symbols, records)

    finding = result.findings[0]
    evidence = finding.evidence[0]
    assert evidence["evidence_level"] == "call-site"
    assert evidence["call_site_count"] == 2
    assert evidence["call_sites"] == ("0x1100", "0x1200")
    assert "calls it at 2 site(s)" in finding.message
    assert result.data["call_site_evidence"] is True
    assert result.data["call_site_confirmed_apis"] == ["system"]
    assert result.data["call_site_confirmed_count"] == 1


def test_import_finding_stays_linkage_when_the_symbol_is_never_called():
    symbols = {
        "imports": [{"name": "system", "source": ".dynsym"}],
        "functions": [],
        "stripped": False,
    }

    result = _analyze_with_callgraph(symbols, [])

    finding = result.findings[0]
    assert finding.evidence[0]["evidence_level"] == "linkage"
    assert finding.evidence[0]["call_site_count"] == 0
    assert "reachable through this symbol" in finding.message
    # The call graph ran, so "no call site" is a fact rather than missing data.
    assert result.data["call_site_evidence"] is True
    assert result.data["call_site_confirmed_count"] == 0


def test_linkage_only_analysis_is_unchanged_without_callgraph():
    symbols = {
        "imports": [{"name": "system", "source": ".dynsym"}],
        "functions": [],
        "stripped": False,
    }

    result = _analyze(symbols)

    finding = result.findings[0]
    assert finding.evidence[0]["evidence_level"] == "linkage"
    assert result.data["call_site_evidence"] is False


def test_optional_callgraph_is_not_a_hard_dependency():
    """A symbol-only plan must not require basic.callgraph."""
    assert SecurityDangerousApiAnalyzer.metadata.requires == ("basic.symbols",)
    assert "basic.callgraph" in SecurityDangerousApiAnalyzer.metadata.optional_requires
