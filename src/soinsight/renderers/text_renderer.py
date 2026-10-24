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
            lines.extend(["", "Findings:"])
            if result.findings:
                lines[-1] = f"Findings: {len(result.findings)}"
                for finding in result.findings:
                    lines.append(
                        f"  [{finding.severity.value}] {finding.title}"
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
