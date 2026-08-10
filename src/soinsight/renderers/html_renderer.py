"""HTML report renderer."""

from html import escape

from ..application import ApplicationResponse
from .base import Renderer


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
        return (
            "<!doctype html>\n"
            "<html><head><meta charset=\"utf-8\">"
            "<title>SOInsight Analysis Report</title>"
            "</head><body>"
            f"{body}"
            "</body></html>\n"
        )
