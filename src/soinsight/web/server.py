"""Simple HTTP server for SOInsight web interface."""

import html
import io
import json
import tempfile
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..application import AnalysisRequest, AnalysisService
from ..core.analyzer import AnalyzerRegistry
from ..core.runtime import AnalysisRuntime, ProgressEvent, ProgressObserver
from ..infrastructure.config import ConfigLoader
from ..renderers import create_default_renderer_registry


class WebProgressObserver(ProgressObserver):
    """Collect progress events for SSE streaming."""

    def __init__(self):
        self.events: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def on_analyzer_start(self, event):
        with self.lock:
            self.events.append({
                "type": "analyzer_start",
                "analyzer_id": event.analyzer_id,
            })

    def on_analyzer_finish(self, event):
        with self.lock:
            self.events.append({
                "type": "analyzer_finish",
                "analyzer_id": event.analyzer_id,
                "status": event.status,
                "duration_ms": event.duration_ms,
            })


class WebRequestHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests for file upload and analysis."""

    def __init__(self, *args, analyzer_registry: AnalyzerRegistry = None, **kwargs):
        self.analyzer_registry = analyzer_registry
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._serve_index()
        elif parsed.path == "/api/health":
            self._serve_json({"status": "ok"})
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)

        if parsed.path == "/api/analyze":
            self._handle_analyze()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _serve_index(self):
        """Serve the index HTML page."""
        template_path = Path(__file__).parent / "templates" / "index.html"
        try:
            content = template_path.read_text(encoding="utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except FileNotFoundError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Template not found")

    def _serve_json(self, data: dict, status: HTTPStatus = HTTPStatus.OK):
        """Serve JSON response."""
        content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_analyze(self):
        """Handle file upload and analysis."""
        content_type = self.headers.get("Content-Type", "")

        if "multipart/form-data" not in content_type:
            self.send_error(HTTPStatus.BAD_REQUEST, "Expected multipart/form-data")
            return

        # Parse multipart form data
        boundary = content_type.split("boundary=")[1].strip()
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Extract file and analyzers
        file_data, analyzers = self._parse_multipart(body, boundary.encode())
        if not file_data:
            self.send_error(HTTPStatus.BAD_REQUEST, "No file uploaded")
            return

        filename, file_content = file_data

        # Default to all analyzers if none specified
        if not analyzers:
            analyzers = [
                "basic.file",
                "basic.elf",
                "basic.symbols",
                "basic.dwarf",
                "advanced.strings",
                "security.hardening",
                "security.dangerous-api",
                "security.risk",
            ]

        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
            tmp.write(file_content)
            tmp_path = Path(tmp.name)

        try:
            # Run analysis
            progress_observer = WebProgressObserver()
            result = self._run_analysis(tmp_path, progress_observer, analyzers)

            # Render HTML
            renderer_registry = create_default_renderer_registry()
            html_renderer = renderer_registry.get("html")
            html_content = html_renderer.render(result)

            # Return result with progress events
            response = {
                "success": True,
                "html": html_content,
                "progress": progress_observer.events,
            }
            self._serve_json(response)

        except Exception as e:
            self._serve_json({
                "success": False,
                "error": str(e),
            }, HTTPStatus.INTERNAL_SERVER_ERROR)

        finally:
            # Cleanup temp file
            tmp_path.unlink(missing_ok=True)

    def _parse_multipart(self, body: bytes, boundary: bytes) -> tuple[tuple[str, bytes] | None, list[str]]:
        """Parse multipart/form-data body and extract file and analyzers."""
        parts = body.split(b"--" + boundary)

        file_data = None
        analyzers = []

        for part in parts[1:-1]:  # Skip first empty and last closing
            if b"Content-Disposition: form-data" not in part:
                continue

            # Extract field name
            lines = part.split(b"\r\n")
            field_name = None
            filename = None
            for line in lines:
                if b'name="' in line:
                    field_name = line.split(b'name="')[1].split(b'"')[0].decode()
                if b"filename=" in line:
                    filename = line.split(b"filename=")[1].strip(b'"').decode()

            if not field_name:
                continue

            # Extract content (after double newline)
            content_start = part.find(b"\r\n\r\n")
            if content_start == -1:
                continue

            content = part[content_start + 4:].rstrip(b"\r\n")

            if field_name == "file" and filename:
                file_data = (filename, content)
            elif field_name == "analyzers":
                # analyzers is a comma-separated string
                analyzers = [a.strip() for a in content.decode().split(",") if a.strip()]

        return file_data, analyzers

    def _run_analysis(self, target_path: Path, progress_observer: ProgressObserver, analyzers: list[str]):
        """Run analysis on the target file."""
        runtime = AnalysisRuntime(self.analyzer_registry)
        config = ConfigLoader().load(cache_enabled=False)
        service = AnalysisService(runtime)

        request = AnalysisRequest(
            target=str(target_path),
            analyzer_ids=analyzers,
            profile=None,
        )

        return service.execute(request, config, observer=progress_observer)


def create_server(host: str, port: int, analyzer_registry: AnalyzerRegistry) -> HTTPServer:
    """Create HTTP server with analyzer registry."""
    def handler_factory(*args, **kwargs):
        return WebRequestHandler(*args, analyzer_registry=analyzer_registry, **kwargs)

    server = HTTPServer((host, port), handler_factory)
    return server


def run_server(host: str = "127.0.0.1", port: int = 8080):
    """Run the web server."""
    from ..analyzers import register_builtin_analyzers

    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)

    server = create_server(host, port, registry)

    print(f"SOInsight Web Server")
    print(f"Listening on http://{host}:{port}")
    print(f"Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
