"""Markdown report renderer."""

from ..application import ApplicationResponse
from .base import Renderer


class MarkdownRenderer(Renderer):
    format = "markdown"

    def render(self, response: ApplicationResponse) -> str:
        if response.result is None:
            return "# SOInsight Analysis Report\n\nNo result.\n"
        result = response.result
        return (
            "# SOInsight Analysis Report\n\n"
            "## Target\n\n"
            f"- Path: `{result.target.path}`\n"
            f"- SHA-256: `{result.target.sha256}`\n"
            f"- Status: `{result.status.value}`\n\n"
            "## Findings\n\n"
            f"{len(result.findings)} finding(s).\n"
        )
