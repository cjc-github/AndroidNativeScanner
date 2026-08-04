"""Human-readable framework renderer."""

from ..application import ApplicationResponse
from .base import Renderer


class TextRenderer(Renderer):
    format = "text"

    def render(self, response: ApplicationResponse) -> str:
        lines: list[str] = []
        if response.result is not None:
            result = response.result
            lines.extend(
                [
                    f"Target: {result.target.path}",
                    f"SHA-256: {result.target.sha256}",
                    f"Status: {result.status.value}",
                    f"Analyzers: {', '.join(result.resolved_analyzers) or '(none)'}",
                    f"Findings: {len(result.findings)}",
                    f"Duration: {result.duration_ms} ms",
                ]
            )
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
