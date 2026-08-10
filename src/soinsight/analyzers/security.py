"""Built-in Security domain analyzers."""

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Finding,
    Severity,
)


class SecurityHardeningAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="security.hardening",
        name="Hardening Analyzer",
        version="1.0.0",
        description="Evaluate basic ELF hardening facts.",
        requires=("basic.elf",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        elf_result = context.require("basic.elf")
        findings: list[Finding] = []
        if elf_result.data.get("type") == "EXEC":
            findings.append(
                Finding(
                    rule_id="security.hardening.executable-elf",
                    rule_version="1.0.0",
                    title="Executable ELF lacks shared-object hardening baseline",
                    category="hardening",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    message="ELF type is EXEC rather than DYN; PIE hardening may be absent.",
                )
            )
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"hardening_summary": {"finding_count": len(findings)}},
            findings=findings,
        )
