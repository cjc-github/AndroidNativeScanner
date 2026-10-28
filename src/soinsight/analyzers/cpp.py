"""Built-in Basic domain C++ structure recovery analyzer.

``basic.cpp`` turns linkage-level evidence into C++ structure facts: RTTI
symbols (``_ZTI*``/``_ZTS*``), vtables (``_ZTV*``/``_ZTT*``), construction
vtables (``_ZTC*``), thunks, constructors and destructors from mangled names,
and inheritance/virtuality from DWARF composite types. Every class record
names the evidence it rests on (DWARF, RTTI, symbols); when a class is
unknown to all of them nothing is reported for it instead of being guessed.
"""

from __future__ import annotations

import re
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

ANALYZER_ID = "basic.cpp"

_DEFAULT_OPTIONS = {
    "max_classes": 10000,
}

# ``short_name`` values the demangler produces for the special-name symbols
# that carry per-class evidence. Everything else (guard variables, TLS
# helpers, reference temporaries) is compiler machinery without class facts.
_CLASS_ROLES = {
    "vtable": "vtable",
    "VTT": "vtt",
    "typeinfo": "typeinfo",
    "typeinfo name": "typeinfo_name",
}

_CLONE_PATTERN = re.compile(r"([CD][0-9])E")
_THUNK_OFFSET_PATTERN = re.compile(r"\((-?\d+)\)$")

_VIRTUAL_THUNK_KINDS = {
    "virtual thunk": "virtual",
    "non-virtual thunk": "non-virtual",
}


class BasicCppAnalyzer(Analyzer):
    """Recover C++ classes, inheritance, vtables and special members."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="C++ Recovery Analyzer",
        version="1.0.0",
        description="Recover C++ classes, inheritance and vtables.",
        requires=("basic.elf", "basic.dwarf", "basic.types"),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        types_result = context.require("basic.types")
        dwarf_result = context.require("basic.dwarf")
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

        classes, class_total, truncated, truncated_lists = _build_classes(
            types_result, dwarf_result, elf, options["max_classes"]
        )
        thunks = _collect_thunks(elf)
        construction_vtables = _collect_construction_vtables(elf)
        lists_truncated = truncated
        if len(thunks) > options["max_classes"]:
            truncated_lists.append(f"thunks {len(thunks)}>{options['max_classes']}")
            lists_truncated = True
        if len(construction_vtables) > options["max_classes"]:
            truncated_lists.append(
                f"construction_vtables {len(construction_vtables)}>{options['max_classes']}"
            )
            lists_truncated = True

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "has_debug_info": bool(types_result.data.get("has_debug_info")),
                "class_count": class_total,
                "vtable_count": sum(1 for c in classes if c["vtable"]),
                "typeinfo_count": sum(1 for c in classes if c["typeinfo"]),
                "constructor_count": sum(len(c["constructors"]) for c in classes),
                "destructor_count": sum(len(c["destructors"]) for c in classes),
                "virtual_method_count": sum(len(c["virtual_methods"]) for c in classes),
                "thunk_count": len(thunks),
                "construction_vtable_count": len(construction_vtables),
                "truncated": lists_truncated,
                "classes": classes,
                "thunks": thunks[: options["max_classes"]],
                "construction_vtables": construction_vtables[: options["max_classes"]],
            },
            diagnostics=[
                Diagnostic(
                    code="CPP_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "C++ output truncated to the option limit: "
                        + ", ".join(truncated_lists)
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            ]
            if lists_truncated
            else [],
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the recovered C++ structure as text."""
        if result.status == AnalysisStatus.FAILED:
            return "=== C++ 恢复失败 ==="
        if result.status != AnalysisStatus.SUCCESS:
            return None

        data = result.data
        lines = [
            "=== C++ 恢复 ===",
            f"类: {data.get('class_count', 0)}",
            f"vtable: {data.get('vtable_count', 0)}    "
            f"typeinfo: {data.get('typeinfo_count', 0)}",
            f"构造函数: {data.get('constructor_count', 0)}    "
            f"析构函数: {data.get('destructor_count', 0)}    "
            f"虚方法: {data.get('virtual_method_count', 0)}",
            f"thunk: {data.get('thunk_count', 0)}    "
            f"构造 vtable: {data.get('construction_vtable_count', 0)}",
        ]
        if data.get("has_debug_info"):
            lines.append("继承来源: DWARF 调试信息")
        else:
            lines.append("继承来源: 无调试信息（基类仅在有 DWARF 时恢复）")

        classes = data.get("classes", [])
        if classes:
            lines.append("")
            lines.append(
                f"=== 类（显示前 {min(15, len(classes))} / 共 {len(classes)} 个）==="
            )
            for record in classes[:15]:
                kind = record.get("kind") or "未知"
                lines.append(f"  {record.get('name', 'N/A')}（{'、'.join(record.get('sources', []))}，{kind}）")
                if record.get("byte_size") is not None:
                    lines.append(f"    大小: {record['byte_size']} 字节")
                for base in record.get("bases", []):
                    extra = " virtual" if base.get("virtual") else ""
                    lines.append(f"    基类: {base.get('name', 'N/A')}{extra}")
                for role, label in (
                    ("vtable", "vtable"),
                    ("typeinfo", "typeinfo"),
                    ("vtt", "VTT"),
                    ("typeinfo_name", "typeinfo name"),
                ):
                    entry = record.get(role)
                    if entry:
                        lines.append(
                            f"    {label}: {entry['symbol']} @ {entry.get('address') or '?'}"
                        )
                for ctor in record.get("constructors", []):
                    lines.append(
                        f"    构造函数: {ctor.get('signature') or ctor.get('linkage_name', '')}"
                        f" [{ctor.get('clone') or '?'}]"
                    )
                for dtor in record.get("destructors", []):
                    lines.append(
                        f"    析构函数: {dtor.get('signature') or dtor.get('linkage_name', '')}"
                        f" [{dtor.get('clone') or '?'}]"
                    )
                for method in record.get("virtual_methods", []):
                    lines.append(f"    虚方法: {method.get('signature') or method.get('name', '')}")

        thunks = data.get("thunks", [])
        if thunks:
            lines.append("")
            lines.append(
                f"=== thunk（显示前 {min(10, len(thunks))} / 共 {len(thunks)} 个）==="
            )
            for thunk in thunks[:10]:
                lines.append(f"  {thunk.get('symbol', '')}: {thunk.get('target', '')}")
        return "\n".join(lines)


def _build_classes(types_result, dwarf_result, elf, max_classes: int):
    """Assemble class records from DWARF types, RTTI symbols and signatures."""
    classes: dict[str, dict] = {}
    truncated = False
    truncated_lists: list[str] = []

    # DWARF composite types are the authoritative view of classes: members,
    # bases and virtuality all come from here when debug info is present.
    dwarf_functions = {
        record.get("linkage_name") or record.get("name"): record
        for record in dwarf_result.data.get("functions", [])
        if record.get("linkage_name") or record.get("name")
    }
    for type_ in types_result.data.get("types", []):
        if type_.get("kind") not in ("class", "struct"):
            continue
        name = type_.get("name", "")
        if not name:
            continue
        classes[name] = {
            "name": name,
            "sources": ["dwarf"],
            "kind": type_.get("kind"),
            "byte_size": type_.get("byte_size"),
            "decl_file": type_.get("decl_file"),
            "decl_line": type_.get("decl_line"),
            "unit_name": type_.get("unit_name", ""),
            "bases": list(type_.get("bases", [])),
            "member_count": len(type_.get("members", [])),
            "vtable": None,
            "vtt": None,
            "typeinfo": None,
            "typeinfo_name": None,
            "constructors": [],
            "destructors": [],
            "virtual_methods": [],
        }

    # RTTI and vtable symbols prove classes exist even without debug
    # information; the demangler yields the class name directly. Imported
    # (undefined) special symbols name classes defined in other objects —
    # most prominently the runtime's own __cxxabiv1 machinery — and are not
    # evidence about this image, so they are ignored.
    symbol_by_name: dict[str, object] = {}
    for symbol in elf.symbols:
        if symbol.is_defined and symbol.name and symbol.name not in symbol_by_name:
            symbol_by_name[symbol.name] = symbol

    for name, symbol in symbol_by_name.items():
        decoded = demangle(name)
        if decoded.kind != "special":
            continue
        entry = _special_entry(symbol)
        if decoded.short_name == "construction vtable":
            continue  # recorded separately: it names two classes, not one
        role = _CLASS_ROLES.get(decoded.short_name)
        if role is None:
            continue
        record = _class_record(classes, decoded.qualified_name, "rtti")
        record[role] = entry

    # Constructors, destructors and virtual methods join the class records by
    # class name; DWARF facts (decl positions, virtuality) win over symbol
    # table facts, mirroring the merge order used by basic.types. The symbol
    # table is walked directly (not via basic.types signatures) because its
    # dedup collapses clone variants such as C1/C2 into the DWARF name.
    for linkage, record in dwarf_functions.items():
        _attach_special_member(classes, linkage, record, "dwarf")

    for symbol in symbol_by_name.values():
        decoded = demangle(symbol.name)
        if decoded.kind not in ("constructor", "destructor"):
            continue
        _attach_special_member(classes, symbol.name, {}, "symbols")

    for record in dwarf_result.data.get("functions", []):
        if not record.get("virtual"):
            continue
        name = record.get("name", "")
        if "::" not in name:
            continue
        class_name, _, method = name.rpartition("::")
        class_record = classes.get(class_name)
        if class_record is None:
            continue
        if method.startswith("~"):
            continue  # virtual destructors are reported under destructors
        linkage = record.get("linkage_name", "")
        existing = {item["linkage_name"] or item["name"] for item in class_record["virtual_methods"]}
        if linkage and linkage in existing:
            continue
        class_record["virtual_methods"].append(
            {
                "name": method,
                "signature": record.get("signature", ""),
                "linkage_name": linkage,
                "decl_file": record.get("decl_file"),
                "decl_line": record.get("decl_line"),
            }
        )

    # Plain C structs reach the DWARF type stream through glibc headers and
    # carry none of the evidence this analyzer cares about (no bases, special
    # members, vtable slots or RTTI names). Capability scope is C++ recovery,
    # so such dwarf-only records are dropped instead of reported.
    for name in [
        name
        for name, record in classes.items()
        if record["sources"] == ["dwarf"]
        and not (
            record["bases"]
            or record["constructors"]
            or record["destructors"]
            or record["virtual_methods"]
            or record["vtable"]
            or record["vtt"]
            or record["typeinfo"]
            or record["typeinfo_name"]
        )
    ]:
        del classes[name]

    ordered = sorted(classes.values(), key=lambda record: record["name"])
    total = len(ordered)
    if total > max_classes:
        truncated = True
        truncated_lists.append(f"classes {total}>{max_classes}")
        ordered = ordered[:max_classes]
    return ordered, total, truncated, truncated_lists


def _class_record(classes: dict[str, dict], class_name: str, source: str) -> dict:
    record = classes.get(class_name)
    if record is None:
        record = {
            "name": class_name,
            "sources": [],
            "kind": None,
            "byte_size": None,
            "decl_file": None,
            "decl_line": None,
            "unit_name": "",
            "bases": [],
            "member_count": 0,
            "vtable": None,
            "vtt": None,
            "typeinfo": None,
            "typeinfo_name": None,
            "constructors": [],
            "destructors": [],
            "virtual_methods": [],
        }
        classes[class_name] = record
    if source not in record["sources"]:
        record["sources"].append(source)
        record["sources"].sort()
    return record


def _special_entry(symbol) -> dict:
    return {
        "symbol": symbol.name,
        "address": hex(symbol.value) if symbol.is_defined else None,
        "size": symbol.size or None,
        "table": symbol.table,
    }


def _attach_special_member(classes: dict[str, dict], linkage: str, record: dict, source: str) -> None:
    """Attach one constructor/destructor symbol to its class record."""
    decoded = demangle(linkage)
    if decoded.kind not in ("constructor", "destructor"):
        return
    if not decoded.namespace:
        return
    clone_match = _CLONE_PATTERN.search(linkage)
    entry = {
        "signature": decoded.display,
        "clone": clone_match.group(1) if clone_match else None,
        "linkage_name": linkage,
        "decl_file": record.get("decl_file"),
        "decl_line": record.get("decl_line"),
        "source": source,
    }
    class_record = _class_record(classes, decoded.namespace, source)
    bucket = "constructors" if decoded.kind == "constructor" else "destructors"
    existing = {item["linkage_name"] for item in class_record[bucket]}
    if linkage not in existing:
        class_record[bucket].append(entry)


def _collect_thunks(elf) -> list[dict]:
    """Collect virtual/non-virtual thunk symbols as flat evidence records."""
    thunks: list[dict] = []
    seen: set[str] = set()
    for symbol in elf.symbols:
        if not symbol.is_defined or symbol.name in seen:
            continue
        seen.add(symbol.name)
        decoded = demangle(symbol.name)
        kind = _VIRTUAL_THUNK_KINDS.get(decoded.short_name)
        if decoded.kind != "special" or kind is None:
            continue
        offset_match = _THUNK_OFFSET_PATTERN.search(decoded.display)
        thunks.append(
            {
                "symbol": symbol.name,
                "kind": kind,
                "target": decoded.qualified_name,
                "offset": int(offset_match.group(1)) if offset_match else None,
                "address": hex(symbol.value),
            }
        )
    return thunks


def _collect_construction_vtables(elf) -> list[dict]:
    """Collect construction vtable symbols (``TC`` special names)."""
    records: list[dict] = []
    seen: set[str] = set()
    for symbol in elf.symbols:
        if not symbol.is_defined or symbol.name in seen:
            continue
        seen.add(symbol.name)
        decoded = demangle(symbol.name)
        if decoded.kind != "special" or decoded.short_name != "construction vtable":
            continue
        records.append(
            {
                "symbol": symbol.name,
                "base": decoded.qualified_name,
                "display": decoded.display,
                "address": hex(symbol.value),
            }
        )
    return records


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    if "max_classes" in declared:
        try:
            value = int(declared["max_classes"])
        except (TypeError, ValueError):
            value = _DEFAULT_OPTIONS["max_classes"]
        resolved["max_classes"] = max(1, min(value, 100000))
    return resolved
