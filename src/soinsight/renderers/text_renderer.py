"""Human-readable framework renderer."""

from ..application import ApplicationResponse
from .base import Renderer


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


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
            lines.extend(["", "Findings:"])
            if result.findings:
                for finding in result.findings:
                    lines.append(f"  - {finding.title}")
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
