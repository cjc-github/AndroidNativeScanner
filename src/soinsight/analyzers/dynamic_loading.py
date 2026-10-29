"""``security.dynamic-loading``: how the loader will bind this image.

``basic.dynamic`` reports what the image *declares*: the libraries it needs,
the search path that decides which file satisfies a dependency, the symbol
versions it demands.  This analyzer judges those declarations.

The questions it answers are the ones a loader hijack would exploit:

* which directories are searched, and can an attacker write into them?
* does the image bind its own symbols first, or let a dependency preempt them?
* are code pages patched at load time (``DT_TEXTREL``)?
"""

from __future__ import annotations

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Diagnostic,
    DiagnosticLevel,
    Finding,
    Severity,
)

ANALYZER_ID = "security.dynamic-loading"

_SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
}

# Directories every process on a Unix-like system can write to.  A shared
# library resolved out of one of them is a library every user on the box can
# replace.
_WORLD_WRITABLE_DIRECTORIES = frozenset(
    {
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/shm",
        "/var/run",
    }
)

# ``$ORIGIN`` is resolved against the object's own directory, so it is a
# relative path by construction and not a hijacking opportunity on its own.
_ORIGIN_PREFIXES = ("$ORIGIN", "${ORIGIN}")


class SecurityDynamicLoadingAnalyzer(Analyzer):
    """Judge the dynamic-linking declarations of an image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Dynamic Loading Risk Analyzer",
        version="1.0.0",
        description=(
            "Judge library search paths, symbol interposition and text "
            "relocations."
        ),
        requires=("basic.dynamic",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        dynamic_result = context.require("basic.dynamic")
        dynamic = dynamic_result.data

        diagnostics: list[Diagnostic] = []
        if not dynamic.get("has_dynamic"):
            diagnostics.append(
                Diagnostic(
                    code="NO_DYNAMIC_SECTION",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "The image carries no dynamic section; there is no "
                        "library loading behaviour to judge."
                    ),
                    analyzer_id=self.metadata.id,
                )
            )

        search_path = list(dynamic.get("search_path") or [])
        relative_entries = _relative_entries(search_path)
        writable_entries = _world_writable_entries(search_path)
        flags = dynamic.get("flags") or {}
        needed = list(dynamic.get("needed") or [])
        version_requirements = (dynamic.get("symbol_versions") or {}).get(
            "requirements"
        ) or []
        versioned_libraries = {item.get("file") for item in version_requirements}

        findings: list[Finding] = []
        if dynamic.get("rpath"):
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.rpath",
                    title="RPATH is inherited by the whole dependency chain",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    message=(
                        "DT_RPATH is searched for every dependency of this "
                        "image, not only for its own libraries; a writable "
                        "entry in the path can hijack them all."
                    ),
                )
            )
        if relative_entries:
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.relative-search-path",
                    title="The library search path contains a relative entry",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    message=(
                        "A relative search path entry lets a library planted "
                        f"in the working directory be loaded instead of the "
                        f"intended one: {', '.join(relative_entries)}."
                    ),
                )
            )
        if writable_entries:
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.world-writable-search-path",
                    title="The library search path contains a world-writable directory",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    message=(
                        "Any local user can replace a library found in "
                        f"{', '.join(writable_entries)}; a process started "
                        "from that path can be made to execute attacker "
                        "controlled code."
                    ),
                )
            )
        if flags.get("textrel"):
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.textrel",
                    title="The image applies relocations to its text segment",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    message=(
                        "DT_TEXTREL makes the loader patch the code pages, "
                        "which requires them to be writable at load time and "
                        "weakens code integrity."
                    ),
                )
            )
        if flags.get("symbolic"):
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.symbolic-binding",
                    title="The image binds its own symbols before the global scope",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    message=(
                        "DF_SYMBOLIC gives this image's definitions priority "
                        "over the global scope, so a dependency can no longer "
                        "preempt them; the same behaviour hides a planted "
                        "definition from other objects."
                    ),
                )
            )
        if flags.get("interpose"):
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.interposition",
                    title="The image interposes on its dependencies",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    message=(
                        "DF_1_INTERPOSE lets this image replace symbols of "
                        "the libraries it loads; the behaviour is legitimate "
                        "for an interposer and hostile for a dropped-in "
                        "library."
                    ),
                )
            )
        unversioned = [
            name
            for name in needed
            if name and name not in versioned_libraries
        ]
        if unversioned and version_requirements:
            findings.append(
                _finding(
                    rule_id="security.dynamic-loading.unversioned-dependency",
                    title="A dependency is required without a symbol version",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    message=(
                        "The image demands no versioned symbol from "
                        f"{', '.join(unversioned)}, so a different build of "
                        "that library satisfies the dependency."
                    ),
                )
            )

        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "needed": needed,
                "needed_count": len(needed),
                "rpath": dynamic.get("rpath"),
                "runpath": dynamic.get("runpath"),
                "search_path": search_path,
                "relative_path_entries": relative_entries,
                "world_writable_entries": writable_entries,
                "textrel": bool(flags.get("textrel")),
                "symbolic": bool(flags.get("symbolic")),
                "interpose": bool(flags.get("interpose")),
                "bind_now": bool(flags.get("bind_now")),
                "versioned_libraries": sorted(
                    name for name in versioned_libraries if name
                ),
                "summary": {"finding_count": len(findings)},
            },
            findings=findings,
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the dynamic-loading risk as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        lines = [
            "=== 动态加载风险 ===",
            f"依赖库 ({data.get('needed_count', 0)}): "
            + ", ".join(data.get("needed", [])),
            f"搜索路径: {', '.join(data.get('search_path', [])) or '-'}",
            "",
        ]
        if result.findings:
            lines.append("=== 风险项 ===")
            for finding in result.findings:
                severity = _SEVERITY_LABELS.get(
                    finding.severity.value, finding.severity.value
                )
                lines.append(f"  [{severity}] {finding.title}")
                lines.append(f"    {finding.message}")
                lines.append("")
        else:
            lines.append("未发现动态加载风险。")
        return "\n".join(lines)


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    message: str,
) -> Finding:
    """Build one finding with the shared rule identity of this analyzer."""
    return Finding(
        rule_id=rule_id,
        rule_version="1.0.0",
        title=title,
        category="dynamic-loading",
        severity=severity,
        confidence=confidence,
        message=message,
    )


def _relative_entries(search_path: list[str]) -> list[str]:
    """Search path entries that are resolved against the working directory."""
    entries = []
    for entry in search_path:
        if not entry or entry.startswith("/"):
            continue
        if entry.startswith(_ORIGIN_PREFIXES):
            continue
        entries.append(entry)
    return entries


def _world_writable_entries(search_path: list[str]) -> list[str]:
    """Search path entries that any local user can write to."""
    entries = []
    for entry in search_path:
        if not entry.startswith("/"):
            continue
        normalized = entry.rstrip("/") or "/"
        if normalized in _WORLD_WRITABLE_DIRECTORIES:
            entries.append(entry)
    return entries
