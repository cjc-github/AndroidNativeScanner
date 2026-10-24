"""Markdown report renderer."""

from ..application import ApplicationResponse
from .base import Renderer

_MARKDOWN_SIGNATURE_LIMIT = 200


class MarkdownRenderer(Renderer):
    format = "markdown"

    def render(self, response: ApplicationResponse) -> str:
        if response.result is None:
            return "# SOInsight Analysis Report\n\nNo result.\n"
        result = response.result
        lines = [
            "# SOInsight Analysis Report",
            "",
            "## Target",
            "",
            f"- Path: `{result.target.path}`",
            f"- SHA-256: `{result.target.sha256}`",
            f"- Status: `{result.status.value}`",
            "",
        ]
        lines.extend(_render_symbols(result))
        lines.extend(
            [
                "## Findings",
                "",
                f"{len(result.findings)} finding(s).",
            ]
        )
        return "\n".join(lines) + "\n"


def _render_symbols(result) -> list[str]:
    """Render the ``basic.symbols`` facts, or nothing when not collected."""
    symbol_result = result.results.get("basic.symbols")
    if symbol_result is None or not symbol_result.data:
        return []
    data = symbol_result.data
    counts = data.get("counts", {})
    lines = [
        "## Symbols",
        "",
        f"- Symbol tables: `{', '.join(data.get('symbol_tables', [])) or 'none'}`",
        f"- Exported functions: {counts.get('exported_functions', 0)}",
        f"- Demangled: {data.get('demangled_count', 0)}",
        f"- JNI methods: {data.get('jni_count', 0)}",
    ]
    if data.get("stripped"):
        lines.append("- Regular symbols: stripped (`.symtab` absent)")
    functions = data.get("functions", [])
    if functions:
        lines.extend(["", "### Exported function signatures", ""])
        for record in functions[:_MARKDOWN_SIGNATURE_LIMIT]:
            signature = record.get("signature", record.get("name", ""))
            lines.append(f"- `{signature}`")
        remaining = len(functions) - _MARKDOWN_SIGNATURE_LIMIT
        if remaining > 0:
            lines.append(f"- ... and {remaining} more")
    lines.append("")
    return lines
