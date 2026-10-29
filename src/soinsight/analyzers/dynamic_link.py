"""``basic.dynamic``: the dynamic-linking facts a shared object declares.

Everything the dynamic linker needs in order to load an image lives in the
``.dynamic`` table and its companions.  This analyzer reports those facts:
the libraries the image needs, the search path that decides which of them
wins, the constructors that run before ``main``, the symbol versions the
image defines and demands, and the relocations that get patched at load
time.

The analyzer reports facts only.  Judging them -- a writable GOT, a
dangerous search path -- belongs to the security domain.
"""

from __future__ import annotations

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.elf import ElfFormatError, parse_elf
from ..infrastructure.elf.constants import (
    DF_1_INITFIRST,
    DF_1_INTERPOSE,
    DF_1_NODEFLIB,
    DF_1_NOW,
    DF_1_ORIGIN,
    DF_1_PIE,
    DF_ORIGIN,
    DF_STATIC_TLS,
    DF_SYMBOLIC,
    DF_TEXTREL,
)
from ..infrastructure.elf.relocations import relocation_type_name

ANALYZER_ID = "basic.dynamic"

_DEFAULT_OPTIONS = {
    "max_relocations": 500,
    "max_symbol_versions": 500,
}


class BasicDynamicAnalyzer(Analyzer):
    """Report the dynamic-linking contract of an image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Dynamic Linking Analyzer",
        version="1.0.0",
        description=(
            "Report dependencies, search paths, constructors, symbol versions "
            "and relocations."
        ),
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []
        try:
            elf = parse_elf(target.real_path)
        except ElfFormatError as exc:
            return AnalysisResult(
                analyzer_id=self.metadata.id,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[
                    Diagnostic(
                        code="INVALID_ELF",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                        analyzer_id=self.metadata.id,
                    )
                ],
            )

        dynamic = elf.dynamic
        if not dynamic.entries:
            diagnostics.append(
                Diagnostic(
                    code="NO_DYNAMIC_SECTION",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "No dynamic section is present; the image is not a "
                        "dynamically linked shared object."
                    ),
                    analyzer_id=self.metadata.id,
                )
            )

        relocations = elf.relocations
        truncated = len(relocations) > options["max_relocations"]
        reported = relocations[: options["max_relocations"]]
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="RELOCATIONS_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The relocation list was truncated to "
                        f"{options['max_relocations']} entries; the counts "
                        "describe the whole image."
                    ),
                    analyzer_id=self.metadata.id,
                )
            )

        versioned = [
            item
            for item in dynamic.symbol_versions
            if item.name and item.index > 1
        ]
        versions_truncated = len(versioned) > options["max_symbol_versions"]
        if versions_truncated:
            versioned = versioned[: options["max_symbol_versions"]]
            diagnostics.append(
                Diagnostic(
                    code="SYMBOL_VERSIONS_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "The versioned symbol list was truncated; the counts "
                        "describe the whole image."
                    ),
                    analyzer_id=self.metadata.id,
                )
            )

        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "has_dynamic": bool(dynamic.entries),
                "needed": list(dynamic.needed),
                "needed_count": len(dynamic.needed),
                "soname": dynamic.soname,
                "rpath": dynamic.rpath,
                "runpath": dynamic.runpath,
                "search_path": _search_path(dynamic),
                "init": hex(dynamic.init) if dynamic.init is not None else None,
                "fini": hex(dynamic.fini) if dynamic.fini is not None else None,
                "init_array": [hex(item) for item in dynamic.init_array],
                "fini_array": [hex(item) for item in dynamic.fini_array],
                "preinit_array": [hex(item) for item in dynamic.preinit_array],
                "constructor_count": len(
                    [item for item in dynamic.init_array if item]
                ),
                "flags": _flags(dynamic),
                "symbol_versions": {
                    "definitions": [
                        {
                            "index": item.index,
                            "name": item.name,
                            "base": item.is_base,
                        }
                        for item in dynamic.version_definitions
                    ],
                    "requirements": [
                        {
                            "name": item.name,
                            "file": item.file,
                            "index": item.index,
                        }
                        for item in dynamic.version_requirements
                    ],
                    "versioned_symbol_count": len(versioned),
                    "versioned_symbols": [
                        {"name": item.name, "index": item.index, "hidden": item.hidden}
                        for item in versioned
                    ],
                    "truncated": versions_truncated,
                },
                "relocations": {
                    "total": len(relocations),
                    "by_section": _by_section(relocations),
                    "import_count": sum(
                        1 for item in relocations if item.symbol_name
                    ),
                    "relative_count": sum(
                        1 for item in relocations if not item.symbol_name
                    ),
                    "entries": [
                        {
                            "section": item.section,
                            "offset": hex(item.offset),
                            "symbol": item.symbol_name,
                            "type": relocation_type_name(item.type),
                            "kind": item.kind,
                        }
                        for item in reported
                    ],
                    "truncated": truncated,
                },
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the dynamic-linking facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 动态链接信息 ===",
            f"依赖库 ({data.get('needed_count', 0)}): "
            + ", ".join(data.get("needed", [])),
            f"SONAME: {data.get('soname') or '-'}",
            f"RPATH: {data.get('rpath') or '-'}",
            f"RUNPATH: {data.get('runpath') or '-'}",
            f"构造函数: {data.get('constructor_count', 0)}",
        ]
        flags = data.get("flags", {})
        if flags:
            enabled = [name for name, value in flags.items() if value]
            lines.append(f"动态标志: {', '.join(enabled) if enabled else '-'}")
        versions = data.get("symbol_versions", {})
        lines.append(
            f"符号版本: 定义 {len(versions.get('definitions', []))}, "
            f"依赖 {len(versions.get('requirements', []))}, "
            f"带版本符号 {versions.get('versioned_symbol_count', 0)}"
        )
        relocations = data.get("relocations", {})
        lines.append(
            f"重定位: {relocations.get('total', 0):,} 条 "
            f"（外部符号 {relocations.get('import_count', 0):,}）"
        )
        return "\n".join(lines)


def _search_path(dynamic) -> list[str]:
    """The library search path entries, in the order the loader uses them."""
    entries: list[str] = []
    for value in (dynamic.rpath, dynamic.runpath):
        if not value:
            continue
        for part in value.split(":"):
            if part and part not in entries:
                entries.append(part)
    return entries


def _flags(dynamic) -> dict:
    """The dynamic flags that change how the loader treats the image."""
    flags = dynamic.flags
    flags_1 = dynamic.flags_1
    return {
        "bind_now": dynamic.bind_now,
        "textrel": dynamic.has_textrel,
        "origin": bool(flags & DF_ORIGIN) or bool(flags_1 & DF_1_ORIGIN),
        "symbolic": bool(flags & DF_SYMBOLIC),
        "static_tls": bool(flags & DF_STATIC_TLS),
        "pie": bool(flags_1 & DF_1_PIE),
        "now": bool(flags_1 & DF_1_NOW),
        "initfirst": bool(flags_1 & DF_1_INITFIRST),
        "interpose": bool(flags_1 & DF_1_INTERPOSE),
        "nodefaultlib": bool(flags_1 & DF_1_NODEFLIB),
    }


def _by_section(relocations) -> dict:
    """Relocation counts per section name."""
    counts: dict[str, int] = {}
    for item in relocations:
        counts[item.section] = counts.get(item.section, 0) + 1
    return counts


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and ranges enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_relocations", "max_symbol_versions"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, min(value, 100000))
    return resolved
