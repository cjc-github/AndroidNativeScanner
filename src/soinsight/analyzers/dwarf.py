"""Built-in Basic domain debug-information analyzer.

``basic.dwarf`` reads DWARF debug information and reports the subprograms it
describes with their parameter names, parameter types, return types and source
locations. That is the one signature detail a dynamic symbol table cannot
carry: ``.dynsym`` gives types for C++ symbols but never parameter names.

Debug information is optional. A stripped release build has none, which is
reported as a fact rather than an error, and any unreadable construct degrades
to ``None`` instead of being guessed at.
"""

from __future__ import annotations

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.dwarf import DwarfFormatError, parse_dwarf
from ..infrastructure.elf import ElfFormatError

ANALYZER_ID = "basic.dwarf"

_DEFAULT_OPTIONS = {
    "max_functions": 10000,
}


class BasicDwarfAnalyzer(Analyzer):
    """Collect debug-information functions with parameters and locations."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="DWARF Analyzer",
        version="1.0.0",
        description="Parse debug information for functions and parameters.",
        requires=("basic.elf",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        try:
            info = parse_dwarf(target.real_path)
        except ElfFormatError as exc:
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[
                    Diagnostic(
                        code="INVALID_ELF",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                        analyzer_id=ANALYZER_ID,
                    )
                ],
            )
        except (DwarfFormatError, OSError) as exc:
            # Malformed debug information must not fail the run: report what
            # could not be read and leave the rest of the analysis intact.
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.SUCCESS,
                data={"has_debug_info": False, "functions": []},
                diagnostics=[
                    Diagnostic(
                        code="DWARF_UNREADABLE",
                        level=DiagnosticLevel.WARNING,
                        message=f"Debug information could not be parsed: {exc}",
                        analyzer_id=ANALYZER_ID,
                    )
                ],
            )

        functions = list(info.functions)
        truncated = len(functions) > options["max_functions"]
        if truncated:
            functions = functions[: options["max_functions"]]

        data = {
            "has_debug_info": info.has_debug_info,
            "version": info.version,
            "units": list(info.units),
            "functions": [_function_record(function) for function in functions],
            "truncated": truncated,
        }
        if not info.has_debug_info:
            data["note"] = "No debug information present (stripped build)."

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data=data,
        )


def _function_record(function) -> dict:
    return {
        "name": function.name,
        "linkage_name": function.linkage_name,
        "signature": function.signature,
        "return_type": function.return_type,
        "parameters": [
            {"name": parameter.name, "type": parameter.type_name}
            for parameter in function.parameters
        ],
        "decl_file": function.decl_file,
        "decl_line": function.decl_line,
        "low_pc": hex(function.low_pc) if function.low_pc is not None else None,
        "unit_name": function.unit_name,
    }


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    if "max_functions" in declared:
        try:
            value = int(declared["max_functions"])
        except (TypeError, ValueError):
            value = _DEFAULT_OPTIONS["max_functions"]
        resolved["max_functions"] = max(1, min(value, 100000))
    return resolved
