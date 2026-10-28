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

from typing import Optional

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
                data={"has_debug_info": False, "functions": [], "types": [], "variables": []},
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
            "types": [_type_record(type_) for type_ in info.types],
            "variables": [_variable_record(variable) for variable in info.variables],
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

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format DWARF analysis result as text."""
        if result.status == AnalysisStatus.FAILED:
            return "=== DWARF 分析失败 ==="

        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        lines = [
            "=== DWARF 调试信息 ===",
            f"有调试信息: {'是' if data.get('has_debug_info') else '否'}",
        ]

        if not data.get('has_debug_info'):
            lines.append("说明: 没有调试信息（已剥离的构建）")
            return "\n".join(lines)

        lines.extend([
            f"DWARF 版本: {data.get('version', 'N/A')}",
            f"编译单元数: {len(data.get('units', []))}",
            "",
        ])

        functions = data.get("functions", [])
        if functions:
            lines.append(f"=== 有调试信息的函数（显示前 {min(20, len(functions))} / 共 {len(functions)} 个）===")
            for func in functions[:20]:
                lines.append(f"  {func.get('name', 'N/A')}")
                if func.get('linkage_name'):
                    lines.append(f"    链接名: {func['linkage_name']}")
                if func.get('signature'):
                    lines.append(f"    签名: {func['signature']}")
                if func.get('return_type'):
                    lines.append(f"    返回类型: {func['return_type']}")
                if func.get('parameters'):
                    lines.append(f"    参数:")
                    for param in func['parameters']:
                        param_name = param.get('name', '未命名')
                        param_type = param.get('type', '未知')
                        lines.append(f"      - {param_name}: {param_type}")
                if func.get('decl_file'):
                    decl_line = func.get('decl_line', '?')
                    lines.append(f"    定义位置: {func['decl_file']}:{decl_line}")
                if func.get('low_pc'):
                    lines.append(f"    地址: {func['low_pc']}")
                lines.append("")

            if len(functions) > 20:
                lines.append(f"  ... 以及另外 {len(functions) - 20} 个函数")

        return "\n".join(lines)



def _type_record(type_) -> dict:
    return {
        "name": type_.name,
        "kind": type_.kind,
        "byte_size": type_.byte_size,
        "decl_file": type_.decl_file,
        "decl_line": type_.decl_line,
        "unit_name": type_.unit_name,
        "members": [
            {
                "name": member.name,
                "type_name": member.type_name,
                "offset": member.offset,
                "accessibility": member.accessibility,
                "static": member.static,
            }
            for member in type_.members
        ],
        "bases": [
            {
                "name": base.name,
                "offset": base.offset,
                "accessibility": base.accessibility,
                "virtual": base.virtual,
            }
            for base in type_.bases
        ],
        "enumerators": [
            {"name": enum.name, "value": enum.value}
            for enum in type_.enumerators
        ],
    }


def _variable_record(variable) -> dict:
    return {
        "name": variable.name,
        "type_name": variable.type_name,
        "decl_file": variable.decl_file,
        "decl_line": variable.decl_line,
        "external": variable.external,
        "unit_name": variable.unit_name,
    }


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
        "virtual": function.virtual,
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
