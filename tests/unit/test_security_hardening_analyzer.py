"""Unit tests for the built-in security hardening analyzer."""

from soinsight.analyzers.security import SecurityHardeningAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig


def _target_and_context(tmp_path, name="app"):
    target_file = tmp_path / name
    target_file.write_bytes(b"placeholder")
    target = AnalysisTarget(target_file, target_file.resolve(), name, 11, "sha")
    context = AnalysisContext("run", target, RuntimeConfig())
    return context


def test_security_hardening_flags_executable_elf(tmp_path):
    context = _target_and_context(tmp_path)
    context.add_result(
        AnalysisResult(
            analyzer_id="basic.elf",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"type": "EXEC", "machine": "x86-64"},
        )
    )

    result = SecurityHardeningAnalyzer().analyze(context.target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert result.findings
    assert result.findings[0].rule_id == "security.hardening.executable-elf"
    assert result.data["hardening_summary"]["finding_count"] == 1


def test_security_hardening_skips_shared_object(tmp_path):
    context = _target_and_context(tmp_path, name="libsample.so")
    context.add_result(
        AnalysisResult(
            analyzer_id="basic.elf",
            analyzer_version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            data={"type": "DYN", "machine": "x86-64"},
        )
    )

    result = SecurityHardeningAnalyzer().analyze(context.target, context)

    assert result.status == AnalysisStatus.SUCCESS
    assert not result.findings
    assert result.data["hardening_summary"]["finding_count"] == 0
