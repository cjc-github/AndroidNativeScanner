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
            body += _render_jni(result)
            body += _render_remaining(result)
        return (
            "<!doctype html>\n"
            "<html><head><meta charset=\"utf-8\">"
            "<title>SOInsight Analysis Report</title>"
            "</head><body>"
            f"{body}"
            "</body></html>\n"
        )


# The analyzers the report renders with a dedicated section.
_DEDICATED = ("basic.symbols", "basic.jni")


def _render_remaining(result) -> str:
    """Render every analyzer that has no dedicated section.

    The report is the only output the packaged web console shows, so an
    analyzer without a section would simply be missing from it. The generic
    form lists the collected fields as key and value pairs; the specialized
    sections above stay the ones to read for their analyzer.
    """
    parts: list[str] = []
    for analyzer_id, entry in result.results.items():
        if analyzer_id in _DEDICATED or not entry.data:
            continue
        parts.append(f"<h2>{escape(analyzer_id)}</h2>")
        parts.append("<ul>")
        for key, value in entry.data.items():
            if isinstance(value, (dict, list)):
                rendered = escape(_short_json(value))
            else:
                rendered = escape(str(value))
            parts.append(f"<li><code>{escape(str(key))}</code>: {rendered}</li>")
        parts.append("</ul>")
    return "".join(parts)


def _short_json(value: object, limit: int = 400) -> str:
    """A compact JSON rendering of a nested value."""
    import json

    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(value)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _render_jni(result) -> str:
    """Render the JNI registration table, or nothing when not collected."""
    jni_result = result.results.get("basic.jni")
    if jni_result is None or not jni_result.data:
        return ""
    data = jni_result.data
    parts = [
        "<h2>JNI registrations</h2>",
        "<ul>",
        f"<li>Static (<code>Java_*</code> exports): {data.get('static_count', 0)}</li>",
        f"<li>Dynamic (<code>RegisterNatives</code>): {data.get('dynamic_count', 0)}"
        f" in {data.get('dynamic_array_count', 0)} arrays</li>",
        f"<li><code>JNI_OnLoad</code>: {'present' if data.get('on_load_present') else 'absent'}</li>",
        "</ul>",
    ]
    registrations = data.get("dynamic_registrations") or []
    if registrations:
        parts.append("<h3>Dynamic registration table</h3>")
        parts.append("<table>")
        parts.append(
            "<tr><th>Method</th><th>Java signature</th><th>Native function</th>"
            "<th>Naming</th><th>Array slot</th></tr>"
        )
        for entry in registrations:
            target = (
                entry.get("function_symbol")
                if entry.get("function_named")
                else f"{entry.get('function_address')} (no symbol name)"
            )
            naming = (
                "fully qualified"
                if entry.get("qualified")
                else "bare name; the Java class needs FindClass at run time"
            )
            parts.append(
                "<tr>"
                f"<td><code>{escape(str(entry.get('method_name', '')))}</code></td>"
                f"<td><code>{escape(str(entry.get('signature', '')))}</code></td>"
                f"<td><code>{escape(str(target))}</code></td>"
                f"<td>{escape(naming)}</td>"
                f"<td><code>{escape(str(entry.get('array_slot', '')))}</code></td>"
                "</tr>"
            )
        parts.append("</table>")
    elif data.get("on_load_present") or data.get("register_natives_imported"):
        parts.append(
            "<p><code>JNI_OnLoad</code> or <code>RegisterNatives</code> is present, "
            "but no array shaped like <code>JNINativeMethod</code> was found.</p>"
        )
    else:
        parts.append(
            "<p>The image does not register natives dynamically "
            "(no <code>JNI_OnLoad</code>, no imported <code>RegisterNatives</code>).</p>"
        )
    return "".join(parts)


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
