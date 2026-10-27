"""Built-in Basic domain recovered-type analyzer.

``basic.types`` turns the debug information and symbol table into a small
type model: function signatures, global variables and composite (class, struct,
union, enum) type definitions with their members and base classes. Where the
symbol table proves a function or data object exists but DWARF is absent or
stripped, the symbol-only fact is reported with an unknown type instead of
being guessed at.
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
from ..infrastructure.elf import ElfFormatError, demangle, parse_elf

ANALYZER_ID = "basic.types"

_KIND_LABELS = {
    "class": "类",
    "struct": "结构体",
    "union": "联合体",
    "enum": "枚举",
}

_LANGUAGE_LABELS = {"c": "C", "c++": "C++", "jni": "JNI", "unknown": "未知"}


class BasicTypesAnalyzer(Analyzer):
    """Recover function signatures, variables and composite types."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Type Recovery Analyzer",
        version="1.0.0",
        description="Recover function signatures, variables and composite types.",
        requires=("basic.elf", "basic.dwarf"),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        dwarf = context.require("basic.dwarf")
        try:
            elf = parse_elf(target.real_path)
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

        signatures = _merge_signatures(dwarf, elf)
        variables = _merge_variables(dwarf, elf)
        types = _format_types(dwarf)

        by_kind: dict[str, int] = {}
        for type_ in types:
            by_kind[type_["kind"]] = by_kind.get(type_["kind"], 0) + 1

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "has_debug_info": bool(dwarf.data.get("has_debug_info")),
                "function_count": len(signatures),
                "variable_count": len(variables),
                "type_count": len(types),
                "by_kind": by_kind,
                "signatures": signatures,
                "variables": variables,
                "types": types,
            },
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the recovered type model as text."""
        if result.status == AnalysisStatus.FAILED:
            return "=== 类型恢复失败 ==="
        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        lines = [
            "=== 类型恢复 ===",
            f"函数签名: {data.get('function_count', 0)}",
            f"变量: {data.get('variable_count', 0)}",
            f"复合类型: {data.get('type_count', 0)}",
        ]
        by_kind = data.get("by_kind", {})
        if by_kind:
            lines.append("按类型种类: " + ", ".join(
                f"{_KIND_LABELS.get(kind, kind)} {count}"
                for kind, count in sorted(by_kind.items())
            ))

        types = data.get("types", [])
        if types:
            lines.append("")
            lines.append(f"=== 复合类型（显示前 {min(15, len(types))} / 共 {len(types)} 个）===")
            for type_ in types[:15]:
                lines.append(f"  {type_.get('name', 'N/A')}（{_KIND_LABELS.get(type_.get('kind'), type_.get('kind', ''))}）")
                if type_.get('byte_size') is not None:
                    lines.append(f"    大小: {type_['byte_size']} 字节")
                for base in type_.get('bases', []):
                    extra = " virtual" if base.get('virtual') else ""
                    lines.append(f"    基类: {base.get('name', 'N/A')}{extra}")
                for member in type_.get('members', []):
                    offset = member.get('offset')
                    offset_text = f"@{offset}" if offset is not None else ""
                    lines.append(f"    成员: {member.get('name', 'N/A')}: {member.get('type') or '未知'}{offset_text}")
                for enum in type_.get('enumerators', []):
                    lines.append(f"    枚举值: {enum.get('name', 'N/A')} = {enum.get('value', '?')}")

        signatures = data.get("signatures", [])
        if signatures:
            lines.append("")
            lines.append(f"=== 函数签名（显示前 {min(15, len(signatures))} / 共 {len(signatures)} 个）===")
            for record in signatures[:15]:
                lines.append(f"  {record.get('signature') or record.get('name', 'N/A')}")

        variables = data.get("variables", [])
        if variables:
            lines.append("")
            lines.append(f"=== 变量（显示前 {min(15, len(variables))} / 共 {len(variables)} 个）===")
            for variable in variables[:15]:
                type_name = variable.get('type_name')
                lines.append(f"  {variable.get('name', 'N/A')}: {type_name or '未知类型'}")

        return "\n".join(lines)


def _merge_signatures(dwarf, elf) -> list[dict]:
    """Merge DWARF signatures with symbol-table signatures.

    ``linkage_name`` is the join key: it appears both in DWARF and in the
    symbol table, so a debugging symbol never duplicates a dynamic one.
    """
    signatures: list[dict] = []
    seen: set[str] = set()

    for record in dwarf.data.get("functions", []):
        key = record.get("linkage_name") or record.get("name")
        if not key or key in seen:
            continue
        seen.add(key)
        if record.get("linkage_name"):
            seen.add(record["linkage_name"])
        if record.get("name"):
            seen.add(record["name"])
        signatures.append(
            {
                "name": record.get("name", ""),
                "linkage_name": record.get("linkage_name", ""),
                "signature": record.get("signature", ""),
                "return_type": record.get("return_type"),
                "parameters": record.get("parameters", []),
                "source": "dwarf",
                "language": "c++" if record.get("linkage_name", "").startswith("_Z") else "c",
            }
        )

    # Add exported function symbols that DWARF did not describe. These carry a
    # demangled signature but no parameter names; report them as symbol facts.
    for symbol in elf.symbols:
        if not symbol.is_exported or not symbol.is_function:
            continue
        decoded = demangle(symbol.name)
        if decoded.kind in ("unmangled", "undecoded"):
            continue
        aliases = (symbol.name, decoded.qualified_name, decoded.display)
        if any(alias in seen for alias in aliases):
            continue
        seen.update(alias for alias in aliases if alias)
        signatures.append(
            {
                "name": decoded.display,
                "linkage_name": symbol.name,
                "signature": decoded.display,
                "return_type": decoded.return_type,
                "parameters": [{"name": "", "type": param} for param in decoded.parameters],
                "source": "symbols",
                "language": "c++",
            }
        )
    return signatures


def _merge_variables(dwarf, elf) -> list[dict]:
    """Merge DWARF variables with exported data symbols."""
    variables: list[dict] = []
    seen: set[str] = set()

    for record in dwarf.data.get("variables", []):
        name = record.get("name", "")
        if not name or name in seen:
            continue
        seen.add(name)
        variables.append(
            {
                "name": name,
                "type_name": record.get("type_name"),
                "decl_file": record.get("decl_file"),
                "decl_line": record.get("decl_line"),
                "external": record.get("external"),
                "source": "dwarf",
            }
        )

    for symbol in elf.symbols:
        if not symbol.is_exported or symbol.type != "OBJECT":
            continue
        if symbol.name in seen:
            continue
        seen.add(symbol.name)
        variables.append(
            {
                "name": symbol.name,
                "type_name": None,
                "decl_file": None,
                "decl_line": None,
                "external": None,
                "address": hex(symbol.value),
                "size": symbol.size,
                "source": "symbols",
            }
        )
    return variables


def _format_types(dwarf) -> list[dict]:
    """Serialize the DWARF composite-type model into JSON-safe records."""
    types: list[dict] = []
    for type_ in dwarf.data.get("types", []):
        raw = {
            "name": type_.get("name", ""),
            "kind": type_.get("kind", ""),
            "byte_size": type_.get("byte_size"),
            "decl_file": type_.get("decl_file"),
            "decl_line": type_.get("decl_line"),
            "unit_name": type_.get("unit_name", ""),
        }
        raw["members"] = [
            {
                "name": member.get("name", ""),
                "type": member.get("type_name"),
                "offset": member.get("offset"),
                "accessibility": member.get("accessibility"),
                "static": bool(member.get("static")),
            }
            for member in type_.get("members", [])
        ]
        raw["bases"] = [
            {
                "name": base.get("name", ""),
                "offset": base.get("offset"),
                "accessibility": base.get("accessibility"),
                "virtual": bool(base.get("virtual")),
            }
            for base in type_.get("bases", [])
        ]
        raw["enumerators"] = [
            {"name": enum.get("name", ""), "value": enum.get("value")}
            for enum in type_.get("enumerators", [])
        ]
        types.append(raw)
    return types
