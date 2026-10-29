"""Human-readable framework renderer."""

from ..application import ApplicationResponse
from .base import Renderer

_TEXT_SIGNATURE_LIMIT = 40


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _dwarf_signatures(result) -> dict[str, str]:
    """Index DWARF signatures by mangled name, when debug info was parsed."""
    dwarf_result = result.results.get("basic.dwarf")
    if dwarf_result is None or not dwarf_result.data.get("has_debug_info"):
        return {}
    return {
        record["linkage_name"]: record["signature"]
        for record in dwarf_result.data.get("functions", [])
        if record.get("linkage_name")
    }


def _render_symbols(result) -> list[str]:
    """Render the ``basic.symbols`` facts as a compact signature list."""
    symbol_result = result.results.get("basic.symbols")
    if symbol_result is None or not symbol_result.data:
        return []
    data = symbol_result.data
    counts = data.get("counts", {})
    dwarf = _dwarf_signatures(result)
    enriched = sum(1 for record in data.get("functions", []) if record["name"] in dwarf)
    lines = [
        "",
        "Symbols:",
        f"  Symbol tables        {', '.join(data.get('symbol_tables', [])) or 'none'}",
        f"  Exported functions   {counts.get('exported_functions', 0)}",
        f"  Demangled            {data.get('demangled_count', 0)}",
        f"  JNI methods          {data.get('jni_count', 0)}",
    ]
    if dwarf:
        lines.append(f"  With parameter names {enriched}")
    if counts.get("exported_unclassified"):
        lines.append(
            f"  Untyped exports      {counts['exported_unclassified']}"
        )
    if data.get("stripped"):
        lines.append("  Regular symbols      stripped (.symtab absent)")
    functions = data.get("functions", [])
    if functions:
        lines.append("  Signatures:")
        for record in functions[:_TEXT_SIGNATURE_LIMIT]:
            # Prefer the DWARF signature: it carries parameter names, which
            # the dynamic symbol table cannot express.
            signature = dwarf.get(record["name"], record.get("signature", ""))
            lines.append(f"    {signature or record.get('name', '')}")
        remaining = len(functions) - _TEXT_SIGNATURE_LIMIT
        if remaining > 0:
            lines.append(f"    ... and {remaining} more")
    return lines


_TEXT_STRING_LIMIT = 5


def _render_strings(result) -> list[str]:
    """Render the ``advanced.strings`` facts, or nothing when not collected."""
    strings_result = result.results.get("advanced.strings")
    if strings_result is None or not strings_result.data:
        return []
    data = strings_result.data
    counts = data.get("counts", {})
    lines = [
        "",
        "Strings:",
        f"  Printable strings    {counts.get('unique_strings', 0)} unique / "
        f"{counts.get('total_strings', 0)} occurrences",
    ]
    classified = data.get("classified", {})
    categories = [
        ("URLs", "url"),
        ("Sensitive", "sensitive"),
        ("Base64 blobs", "base64"),
    ]
    summary = ", ".join(
        f"{label} {_category_count(classified, category)}"
        for label, category in categories
    )
    lines.append(f"  Classified           {summary}")
    for label, category in categories:
        shown = classified.get(category, {}).get("hits", [])[:_TEXT_STRING_LIMIT]
        for hit in shown:
            lines.append(f"    {label}: {_elide(str(hit.get('value', '')))}")
        remainder = _category_count(classified, category) - len(shown)
        if remainder > 0:
            lines.append(f"    {label}: ... and {remainder} more")
    return lines


def _render_dynamic(result) -> list[str]:
    """Render the ``basic.dynamic`` facts, or nothing when not collected."""
    dynamic_result = result.results.get("basic.dynamic")
    if dynamic_result is None or not dynamic_result.data:
        return []
    data = dynamic_result.data
    if not data.get("has_dynamic"):
        return []
    lines = [
        "",
        "Dynamic linking:",
        f"  Needed libraries     {data.get('needed_count', 0)}",
    ]
    for name in data.get("needed", []):
        lines.append(f"    {name}")
    if data.get("soname"):
        lines.append(f"  SONAME               {data['soname']}")
    for label, key in (("RPATH", "rpath"), ("RUNPATH", "runpath")):
        if data.get(key):
            lines.append(f"  {label:<20} {data[key]}")
    lines.append(
        f"  Constructors         {data.get('constructor_count', 0)}"
    )
    versions = data.get("symbol_versions", {})
    lines.append(
        f"  Symbol versions      {versions.get('versioned_symbol_count', 0)} "
        f"symbol(s), "
        f"{len(versions.get('requirements', []))} requirement(s)"
    )
    relocations = data.get("relocations", {})
    lines.append(
        f"  Relocations          {relocations.get('total', 0):,} "
        f"({relocations.get('import_count', 0):,} to external symbols)"
    )
    return lines


_TEXT_XREF_LIMIT = 8


def _render_xrefs(result) -> list[str]:
    """Render the ``basic.xref`` facts, or nothing when not collected."""
    xref_result = result.results.get("basic.xref")
    if xref_result is None or not xref_result.data:
        return []
    data = xref_result.data
    lines = [
        "",
        "Cross references:",
        f"  Strings              {data.get('string_count', 0)}",
        f"  Referenced strings   {data.get('referenced_string_count', 0)}",
        f"  Code references      {data.get('xref_count', 0)}",
    ]
    if data.get("truncated"):
        lines.append("  (truncated)")
    for entry in data.get("xrefs", [])[:_TEXT_XREF_LIMIT]:
        value = entry.get("string", "")
        lines.append(
            f"    {entry.get('instruction_address')} -> "
            f"{entry.get('string_address')} "
            f"[{entry.get('kind')}] {_elide(value)}"
        )
    remainder = data.get("xref_count", 0) - min(
        len(data.get("xrefs", [])), _TEXT_XREF_LIMIT
    )
    if remainder > 0:
        lines.append(f"    ... and {remainder} more")
    return lines


_TEXT_LISTING_LIMIT = 6


def _render_formats(result) -> list[str]:
    """Render the ``advanced.file-format`` facts, or nothing when not collected."""
    result_item = result.results.get("advanced.file-format")
    if result_item is None or not result_item.data:
        return []
    data = result_item.data
    lines = [
        "",
        "File formats:",
        f"  Outer                {data.get('outer_format') or 'unknown'}",
        f"  Embedded hits        {data.get('format_count', 0)}"
        f" ({data.get('verified_count', 0)} verified)",
    ]
    for entry in data.get("formats", [])[:_TEXT_LISTING_LIMIT]:
        section = entry.get("section") or "file"
        marker = "ok" if entry.get("verified") else "magic"
        lines.append(
            f"    {entry.get('offset')} {entry.get('format')} [{section}] {marker}"
        )
    remaining = data.get("format_count", 0) - min(
        len(data.get("formats", [])), _TEXT_LISTING_LIMIT
    )
    if remaining > 0:
        lines.append(f"    ... and {remaining} more")
    return lines


def _render_libraries(result) -> list[str]:
    """Render the ``advanced.library`` facts, or nothing when not collected."""
    result_item = result.results.get("advanced.library")
    if result_item is None or not result_item.data:
        return []
    data = result_item.data
    lines = [
        "",
        "Libraries:",
        f"  Identified           {data.get('library_count', 0)}"
        f" ({data.get('corroborated_count', 0)} corroborated)",
    ]
    for item in data.get("libraries", [])[:_TEXT_LISTING_LIMIT]:
        details = ", ".join(ev.get("detail") for ev in item.get("evidence", [])[:2])
        lines.append(f"    {item.get('library')} [{item.get('family')}] {details}")
    remaining = data.get("library_count", 0) - min(
        len(data.get("libraries", [])), _TEXT_LISTING_LIMIT
    )
    if remaining > 0:
        lines.append(f"    ... and {remaining} more")
    return lines


def _render_compilers(result) -> list[str]:
    """Render the ``advanced.compiler`` facts, or nothing when not collected."""
    result_item = result.results.get("advanced.compiler")
    if result_item is None or not result_item.data:
        return []
    data = result_item.data
    lines = [
        "",
        "Toolchain:",
        f"  Identified           {data.get('toolchain_count', 0)}"
        f" ({data.get('corroborated_count', 0)} corroborated)",
    ]
    if data.get("has_build_id"):
        lines.append("  Build ID             present")
    if data.get("has_android_ident"):
        lines.append("  Android note         present")
    for item in data.get("toolchains", [])[:_TEXT_LISTING_LIMIT]:
        version = f" v{item.get('version')}" if item.get("version") else ""
        lines.append(f"    {item.get('toolchain')}{version}")
    return lines


def _render_protocols(result) -> list[str]:
    """Render the ``advanced.protocol`` facts, or nothing when not collected."""
    result_item = result.results.get("advanced.protocol")
    if result_item is None or not result_item.data:
        return []
    data = result_item.data
    lines = [
        "",
        "Protocols:",
        f"  Identified           {data.get('protocol_count', 0)}"
        f" ({data.get('corroborated_count', 0)} corroborated)",
    ]
    for item in data.get("protocols", [])[:_TEXT_LISTING_LIMIT]:
        lines.append(f"    {item.get('protocol')} [{item.get('family')}]")
    remaining = data.get("protocol_count", 0) - min(
        len(data.get("protocols", [])), _TEXT_LISTING_LIMIT
    )
    if remaining > 0:
        lines.append(f"    ... and {remaining} more")
    return lines


def _render_obfuscation(result) -> list[str]:
    """Render the ``advanced.obfuscation`` facts, or nothing when not collected."""
    result_item = result.results.get("advanced.obfuscation")
    if result_item is None or not result_item.data:
        return []
    data = result_item.data
    lines = [
        "",
        "Obfuscation:",
        f"  Signals              {data.get('signal_count', 0)}"
        f" ({data.get('corroborated_count', 0)} corroborated)",
    ]
    for item in data.get("signals", [])[:_TEXT_LISTING_LIMIT]:
        lines.append(f"    {item.get('signal')} [{item.get('category')}]")
    return lines


def _category_count(classified: dict, category: str) -> int:
    return int(classified.get(category, {}).get("count", 0) or 0)


def _elide(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class TextRenderer(Renderer):
    format = "text"

    def render(self, response: ApplicationResponse) -> str:
        lines: list[str] = []
        if response.result is not None:
            result = response.result
            lines.extend(
                [
                    "Target:",
                    f"  Path       {result.target.path}",
                    f"  Size       {_format_bytes(result.target.size)}",
                    f"  SHA-256    {result.target.sha256}",
                    "",
                    "Analysis:",
                ]
            )
            for analyzer_id in result.resolved_analyzers:
                analyzer_result = result.results.get(analyzer_id)
                if analyzer_result is None:
                    continue
                lines.append(
                    f"  {analyzer_id}  {analyzer_result.status.value}  "
                    f"{analyzer_result.duration_ms} ms"
                )
            file_result = result.results.get("basic.file")
            if file_result is not None and file_result.data:
                lines.extend(
                    [
                        "",
                        "File facts:",
                        f"  Format      {file_result.data.get('format', 'unknown')}",
                        f"  Magic       {file_result.data.get('magic', '')}",
                        f"  Name        {file_result.data.get('name', result.target.name)}",
                    ]
                )
            lines.extend(_render_symbols(result))
            lines.extend(_render_dynamic(result))
            lines.extend(_render_strings(result))
            lines.extend(_render_xrefs(result))
            lines.extend(_render_formats(result))
            lines.extend(_render_libraries(result))
            lines.extend(_render_compilers(result))
            lines.extend(_render_protocols(result))
            lines.extend(_render_obfuscation(result))
            lines.extend(["", "Findings:"])
            if result.findings:
                suppressed = sum(1 for item in result.findings if item.suppressed)
                label = f"Findings: {len(result.findings)}"
                if suppressed:
                    label += f" ({suppressed} baselined)"
                lines[-1] = label
                for finding in result.findings:
                    marker = " [baselined]" if finding.suppressed else ""
                    lines.append(
                        f"  [{finding.severity.value}] {finding.title}{marker}"
                    )
            else:
                lines.append("  none")
            diagnostics = result.diagnostics
        else:
            diagnostics = response.diagnostics

        if diagnostics:
            if lines:
                lines.append("")
            lines.append("Diagnostics:")
            for diagnostic in diagnostics:
                lines.append(
                    f"- [{diagnostic.level.value}] {diagnostic.code}: "
                    f"{diagnostic.message}"
                )

        if not lines:
            lines.append("SOInsight completed without output.")
        return "\n".join(lines) + "\n"
