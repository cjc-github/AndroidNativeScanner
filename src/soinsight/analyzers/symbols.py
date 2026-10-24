"""Built-in Basic domain symbol analyzer.

``basic.symbols`` enumerates the functions a shared object exports and
recovers as much signature information as the binary itself retains:

* symbol facts from ``.dynsym``/``.symtab`` (bind, visibility, address, size);
* C++ parameter types decoded from the Itanium ABI mangled name;
* the Java package, class, method and argument types decoded from a JNI
  native method name.

A stripped release ``.so`` keeps ``.dynsym`` but drops ``.symtab``, so local
symbols and DWARF-derived parameter names are unavailable; the analyzer reports
what it can prove and never invents types.
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
from ..infrastructure.elf import (
    ElfFile,
    ElfFormatError,
    Symbol,
    decode_jni_symbol,
    demangle,
    parse_elf,
)

ANALYZER_ID = "basic.symbols"

_DEFAULT_OPTIONS = {
    "demangle": True,
    "jni_decode": True,
    "include_data_symbols": False,
    "include_imports": False,
    "max_functions": 10000,
}

_DYNSYM = ".dynsym"
_SYMTAB = ".symtab"


class BasicSymbolsAnalyzer(Analyzer):
    """Collect exported symbols and recover function signatures."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Symbol Analyzer",
        version="1.0.0",
        description="Enumerate exported symbols and recover function signatures.",
        requires=("basic.elf",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []
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

        tables = _present_tables(elf)
        if not tables:
            diagnostics.append(
                Diagnostic(
                    code="NO_SYMBOL_TABLE",
                    level=DiagnosticLevel.WARNING,
                    message="No dynamic or regular symbol table is present.",
                    analyzer_id=ANALYZER_ID,
                )
            )

        exported_functions: list[dict] = []
        exported_data: list[dict] = []
        unclassified: list[dict] = []
        imports: list[dict] = []
        local_count = 0
        exported_data_count = 0
        import_count = 0
        unclassified_count = 0
        seen_exported: set[str] = set()
        seen_imports: set[str] = set()

        # .dynsym is parsed before .symtab, so the dynamic symbol table wins
        # when the same export appears in both.
        for symbol in elf.symbols:
            if not symbol.is_defined:
                if symbol.name and symbol.name not in seen_imports:
                    seen_imports.add(symbol.name)
                    import_count += 1
                    if options["include_imports"]:
                        imports.append(_import_record(symbol))
                continue
            if symbol.bind == "LOCAL":
                local_count += 1
                continue
            if symbol.name in seen_exported:
                continue
            if symbol.is_function:
                seen_exported.add(symbol.name)
                exported_functions.append(_function_record(symbol, options))
            elif symbol.type == "OBJECT":
                seen_exported.add(symbol.name)
                exported_data_count += 1
                if options["include_data_symbols"]:
                    exported_data.append(_data_record(symbol))
            else:
                # A defined global symbol with no type: typically assembly
                # code built without a ".type" directive. It is part of the
                # export table and callable, but nothing proves it is a
                # function, so it is reported separately rather than guessed.
                seen_exported.add(symbol.name)
                unclassified_count += 1
                unclassified.append(_data_record(symbol))

        truncated = len(exported_functions) > options["max_functions"]
        if truncated:
            exported_functions = exported_functions[: options["max_functions"]]
            diagnostics.append(
                Diagnostic(
                    code="SYMBOLS_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"Exported function list truncated to "
                        f"{options['max_functions']} entries."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        demangled_count = sum(
            1 for record in exported_functions if record["demangled"] is not None
        )
        jni_count = sum(1 for record in exported_functions if record["jni"] is not None)

        data = {
            "symbol_tables": list(tables),
            "stripped": elf.is_stripped,
            "counts": {
                "exported_functions": len(exported_functions),
                "exported_data": exported_data_count,
                "exported_unclassified": unclassified_count,
                "imports": import_count,
                "local": local_count,
            },
            "demangled_count": demangled_count,
            "jni_count": jni_count,
            "functions": exported_functions,
            # Always reported: these are part of the export table, so dropping
            # them silently would understate what the library exposes.
            "unclassified_symbols": unclassified,
        }
        if options["include_data_symbols"]:
            data["data_symbols"] = exported_data
        if options["include_imports"]:
            data["imports"] = imports

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data=data,
            diagnostics=diagnostics,
        )


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and ranges enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("demangle", "jni_decode", "include_data_symbols", "include_imports"):
        if key in declared:
            resolved[key] = bool(declared[key])
    if "max_functions" in declared:
        try:
            value = int(declared["max_functions"])
        except (TypeError, ValueError):
            value = _DEFAULT_OPTIONS["max_functions"]
        resolved["max_functions"] = max(1, min(value, 100000))
    return resolved


def _present_tables(elf: ElfFile) -> tuple[str, ...]:
    tables: list[str] = []
    if elf.has_section(_DYNSYM):
        tables.append(_DYNSYM)
    if elf.has_section(_SYMTAB):
        tables.append(_SYMTAB)
    return tuple(tables)


def _function_record(symbol: Symbol, options: dict) -> dict:
    record = {
        "name": symbol.name,
        "signature": symbol.name,
        "language": "c",
        "kind": "function",
        "namespace": "",
        "short_name": symbol.name,
        "parameters": [],
        "return_type": None,
        "bind": symbol.bind,
        "visibility": symbol.visibility,
        "address": hex(symbol.value),
        "size": symbol.size,
        "source": _table_name(symbol),
        "demangled": None,
        "jni": None,
    }

    jni = decode_jni_symbol(symbol.name) if options["jni_decode"] else None
    if jni is not None:
        record["language"] = "jni"
        record["namespace"] = jni.qualified_name.rpartition(".")[0]
        record["short_name"] = jni.method
        record["parameters"] = list(jni.parameters)
        record["return_type"] = jni.return_type
        record["signature"] = _jni_signature(jni)
        record["jni"] = {
            "package": jni.package,
            "class": jni.class_name,
            "method": jni.method,
            "parameters": list(jni.parameters),
            "return_type": jni.return_type,
        }
        return record

    if options["demangle"]:
        decoded = demangle(symbol.name)
        if decoded.kind not in ("unmangled", "undecoded"):
            record["language"] = "c++"
            record["kind"] = decoded.kind
            record["namespace"] = decoded.namespace
            record["short_name"] = decoded.short_name
            record["parameters"] = list(decoded.parameters)
            record["return_type"] = decoded.return_type
            record["signature"] = decoded.display
            record["demangled"] = {
                "display": decoded.display,
                "kind": decoded.kind,
                "qualified_name": decoded.qualified_name,
                "namespace": decoded.namespace,
                "short_name": decoded.short_name,
                "parameters": list(decoded.parameters),
                "return_type": decoded.return_type,
            }
    return record


def _jni_signature(jni) -> str:
    if jni.parameters or jni.return_type:
        rendered = ", ".join(jni.parameters)
        if jni.return_type:
            return f"{jni.return_type} {jni.qualified_name}({rendered})"
        return f"{jni.qualified_name}({rendered})"
    return jni.qualified_name


def _data_record(symbol: Symbol) -> dict:
    return {
        "name": symbol.name,
        "bind": symbol.bind,
        "visibility": symbol.visibility,
        "address": hex(symbol.value),
        "size": symbol.size,
        "source": _table_name(symbol),
    }


def _import_record(symbol: Symbol) -> dict:
    return {
        "name": symbol.name,
        "kind": symbol.type,
        "source": _table_name(symbol),
    }


def _table_name(symbol: Symbol) -> str:
    return symbol.table if symbol.table in (_DYNSYM, _SYMTAB) else _DYNSYM
