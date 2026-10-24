"""HTML report renderer."""

from html import escape

from ..application import ApplicationResponse
from .base import Renderer

_HTML_SIGNATURE_LIMIT = 500


class HtmlRenderer(Renderer):
    format = "html"

    def render(self, response: ApplicationResponse) -> str:
        if response.result is None:
            body = "<p>No result.</p>"
        else:
            result = response.result
            body = (
                "<h1>SOInsight Analysis Report</h1>"
                "<h2>Target</h2>"
                f"<p><strong>Path:</strong> {escape(str(result.target.path))}</p>"
                f"<p><strong>SHA-256:</strong> {escape(result.target.sha256)}</p>"
                f"<p><strong>Status:</strong> {escape(result.status.value)}</p>"
            )
            body += _render_symbols(result)
        return (
            "<!doctype html>\n"
            "<html><head><meta charset=\"utf-8\">"
            "<title>SOInsight Analysis Report</title>"
            "</head><body>"
            f"{body}"
            "</body></html>\n"
        )


def _render_symbols(result) -> str:
    """Render the ``basic.symbols`` facts, or nothing when not collected."""
    symbol_result = result.results.get("basic.symbols")
    if symbol_result is None or not symbol_result.data:
        return ""
    data = symbol_result.data
    counts = data.get("counts", {})
    dwarf = _dwarf_signatures(result)
    enriched = sum(1 for record in data.get("functions", []) if record["name"] in dwarf)
    parts = [
        "<h2>Symbols</h2>",
        "<ul>",
        f"<li>Symbol tables: <code>"
        f"{escape(', '.join(data.get('symbol_tables', [])) or 'none')}</code></li>",
        f"<li>Exported functions: {counts.get('exported_functions', 0)}</li>",
        f"<li>Demangled: {data.get('demangled_count', 0)}</li>",
        f"<li>JNI methods: {data.get('jni_count', 0)}</li>",
    ]
    if dwarf:
        parts.append(f"<li>With parameter names: {enriched}</li>")
    if data.get("stripped"):
        parts.append("<li>Regular symbols: stripped (<code>.symtab</code> absent)</li>")
    parts.append("</ul>")
    functions = data.get("functions", [])
    if functions:
        parts.append("<h3>Exported function signatures</h3><ul>")
        for record in functions[:_HTML_SIGNATURE_LIMIT]:
            # Prefer the DWARF signature: it carries parameter names, which
            # the dynamic symbol table cannot express.
            signature = dwarf.get(record["name"], record.get("signature", ""))
            parts.append(
                f"<li><code>{escape(signature or record.get('name', ''))}</code></li>"
            )
        remaining = len(functions) - _HTML_SIGNATURE_LIMIT
        if remaining > 0:
            parts.append(f"<li>... and {remaining} more</li>")
        parts.append("</ul>")
    return "".join(parts)


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
