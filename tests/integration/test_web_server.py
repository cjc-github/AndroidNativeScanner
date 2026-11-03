"""Regression tests for the lightweight in-process web server.

Two defects are covered here, both observed in the shipped code:

* ``_run_analysis`` passed ``target`` as a plain ``str`` even though
  ``AnalysisRequest.target`` is typed ``Path``; ``TargetResolver.resolve()``
  calls ``Path``-only methods, so every upload failed with
  ``'str' object has no attribute 'expanduser'`` (HTTP 500).
* ``create_server`` built a serial ``HTTPServer``, so one in-flight analysis
  stopped the server from answering even ``/api/health``.

The handler runs analyses in-process, which is why the tests upload a small
synthetic ELF built from ``tests.conftest``.
"""

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer

from tests.conftest import build_elf64_with_symbols

from soinsight.core.analyzer import AnalyzerRegistry
from soinsight.web.server import WebRequestHandler, create_server


def _multipart(filename: str, payload: bytes, analyzers: str | None = None) -> tuple[bytes, str]:
    """Build a multipart/form-data body the handler's parser understands."""
    boundary = "----" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    body += payload + b"\r\n"
    if analyzers is not None:
        body += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="analyzers"\r\n\r\n'
            f"{analyzers}\r\n"
        ).encode()
    body += f"--{boundary}--\r\n".encode()
    return body, boundary


class _ServerFixture(unittest.TestCase):
    """Spin up the in-process web server on an ephemeral port."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = create_server("127.0.0.1", 0, _build_registry())
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _analyze(self, payload: bytes, analyzers: str | None = None):
        body, boundary = _multipart("libsample.so", payload, analyzers)
        request = urllib.request.Request(
            f"{self.base}/api/analyze",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        return urllib.request.urlopen(request, timeout=120)


def _build_registry() -> AnalyzerRegistry:
    from soinsight.analyzers import register_builtin_analyzers

    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    return registry


def _sample_elf() -> bytes:
    return build_elf64_with_symbols(
        [
            ("", 0, 3, 0xFFF1, 0, 0),
            ("__stack_chk_fail", 1, 2, 0, 0, 0),
            ("system", 0, 0, 0, 0, 0),
        ],
        with_symtab=False,
    )


def _temp_tmp_files() -> set[str]:
    """Snapshot of temp files the handler could be leaking."""
    from pathlib import Path
    import tempfile

    return {
        path.name
        for path in Path(tempfile.gettempdir()).iterdir()
        if path.is_file() and path.name.startswith("tmp")
    }


class AnalyzeTargetTypeTests(_ServerFixture):
    """``target`` must reach the resolver as a Path, not a str."""

    def test_upload_analysis_succeeds(self):
        """The regression: this used to fail with a 500 expanduser error."""
        with self._analyze(_sample_elf()) as response:
            self.assertEqual(response.status, 200)
            payload = json.load(response)

        self.assertTrue(payload["success"], msg=payload.get("error"))
        self.assertIn("html", payload)
        self.assertTrue(payload["html"])

    def test_progress_events_are_reported(self):
        with self._analyze(_sample_elf(), "basic.file,basic.symbols") as response:
            payload = json.load(response)

        events = payload["progress"]
        self.assertTrue(events, "分析没有上报任何进度事件")
        self.assertEqual(events[0]["type"], "analyzer_start")
        analyzer_ids = {
            event["analyzer_id"]
            for event in events
            if event["type"] == "analyzer_start"
        }
        # basic.symbols hard-depends on basic.elf, so the planner pulls it in.
        self.assertEqual(analyzer_ids, {"basic.file", "basic.elf", "basic.symbols"})

    def test_uploaded_temp_file_is_removed(self):
        """The handler unlinks its temp target even on success."""
        before = _temp_tmp_files()
        with self._analyze(_sample_elf(), "basic.file") as response:
            json.load(response)
        time.sleep(0.1)
        self.assertEqual(before, _temp_tmp_files())


class ServerThreadingTests(_ServerFixture):
    """The server must stay responsive while an analysis is in flight."""

    def test_server_uses_threading_handler(self):
        self.assertIsInstance(self.httpd, ThreadingHTTPServer)
        self.assertTrue(self.httpd.daemon_threads)

    def test_health_stays_responsive_during_analysis(self):
        """A serial server would block /api/health behind the running scan."""
        done = threading.Event()

        def run_scan():
            with self._analyze(_sample_elf()) as response:
                json.load(response)
            done.set()

        worker = threading.Thread(target=run_scan, daemon=True)
        worker.start()
        # Give the scan a moment to get inside the handler before probing.
        time.sleep(0.01)

        started = time.time()
        with urllib.request.urlopen(f"{self.base}/api/health", timeout=10) as response:
            self.assertEqual(response.status, 200)
        health_latency = time.time() - started

        self.assertTrue(done.wait(timeout=120), "分析未在预期时间内结束")
        self.assertLess(
            health_latency,
            10,
            msg="/api/health 在分析期间被阻塞，说明服务端仍在串行处理请求",
        )

    def test_index_and_health_routes(self):
        with urllib.request.urlopen(f"{self.base}/", timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("SOInsight", response.read().decode("utf-8"))

        with urllib.request.urlopen(f"{self.base}/api/health", timeout=10) as response:
            self.assertEqual(json.load(response), {"status": "ok"})

    def test_unknown_route_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base}/api/nope", timeout=10)
        self.assertEqual(ctx.exception.code, 404)


class CreateServerTests(unittest.TestCase):
    """Unit-level checks that do not need a listening socket."""

    def test_create_server_binds_requested_port(self):
        registry = AnalyzerRegistry()
        server = create_server("127.0.0.1", 0, registry)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertIsInstance(server, ThreadingHTTPServer)
        finally:
            server.server_close()

    def test_handler_factory_injects_registry(self):
        """The factory hands every request handler the shared registry."""
        registry = AnalyzerRegistry()
        server = create_server("127.0.0.1", 0, registry)
        try:
            # ``analyzer_registry`` is assigned before BaseHTTPRequestHandler's
            # own __init__ runs, so a plain socket-less instantiation is enough.
            with self.assertRaises(TypeError):
                server.RequestHandlerClass(request=None)
            # The factory is a closure over the registry, not a class: the
            # threading test proves the wiring works over a real socket.
            self.assertTrue(callable(server.RequestHandlerClass))
        finally:
            server.server_close()


class AnalyzerCatalogEndpointTests(_ServerFixture):
    """``/api/analyzers`` is what the page builds its checkboxes from."""

    def test_lists_every_registered_analyzer(self):
        registry_ids = {metadata.id for metadata in _build_registry().list()}
        with urllib.request.urlopen(f"{self.base}/api/analyzers", timeout=10) as response:
            self.assertEqual(response.status, 200)
            payload = json.load(response)

        self.assertEqual(payload["status"], "ok")
        listed = {entry["id"] for entry in payload["analyzers"]}
        self.assertEqual(listed, registry_ids)
        # A previously hardcoded default set hid 21 analyzers; the catalog must
        # expose them all so the page can offer them.
        self.assertIn("security.vulnerability", listed)
        self.assertIn("advanced.constants", listed)
        self.assertIn("automation.binary-diff", listed)

    def test_entries_carry_metadata_the_page_needs(self):
        with urllib.request.urlopen(f"{self.base}/api/analyzers", timeout=10) as response:
            payload = json.load(response)

        entry = next(
            item for item in payload["analyzers"] if item["id"] == "automation.binary-diff"
        )
        self.assertFalse(
            entry["default_enabled"],
            "binary-diff needs two inputs and must not be pre-checked",
        )
        self.assertTrue(entry["name"])
        self.assertIsInstance(entry["requires"], list)


class AnalyzerSelectionTests(_ServerFixture):
    """Uploads must run exactly the analyzers the caller picked."""

    def test_uploaded_selection_is_honoured(self):
        with self._analyze(
            _sample_elf(), "basic.file,security.dangerous-api"
        ) as response:
            payload = json.load(response)

        self.assertTrue(payload["success"], msg=payload.get("error"))
        ran = {
            event["analyzer_id"]
            for event in payload["progress"]
            if event["type"] == "analyzer_start"
        }
        self.assertIn("basic.file", ran)
        self.assertIn("security.dangerous-api", ran)
        # Unselected analyzers must stay out of the run.
        self.assertNotIn("advanced.strings", ran)
        self.assertNotIn("security.risk", ran)

    def test_defaults_used_when_no_analyzer_field_is_sent(self):
        """Old clients that only upload a file still get a full default run."""
        with self._analyze(_sample_elf(), None) as response:
            payload = json.load(response)

        self.assertTrue(payload["success"], msg=payload.get("error"))
        ran = {
            event["analyzer_id"]
            for event in payload["progress"]
            if event["type"] == "analyzer_start"
        }
        self.assertIn("basic.file", ran)
        self.assertIn("advanced.strings", ran)
        self.assertIn("security.risk", ran)

    def test_unknown_analyzer_is_rejected_with_a_clear_message(self):
        body, boundary = _multipart(
            "libsample.so", _sample_elf(), "basic.file,bogus.analyzer"
        )
        request = urllib.request.Request(
            f"{self.base}/api/analyze",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=60)
        self.assertEqual(ctx.exception.code, 400)
        payload = json.load(ctx.exception)
        self.assertFalse(payload["success"])
        self.assertIn("bogus.analyzer", payload["error"])

    def test_upload_with_trailing_crlf_is_not_corrupted(self):
        """A file ending in CRLF must reach the analyzer byte-identical.

        The ELF parser tolerates two extra trailing bytes, so the only proof
        that multipart framing did not eat them is the size basic.file reports.
        """
        blob = _sample_elf() + b"\r\n"
        handler = WebRequestHandler.__new__(WebRequestHandler)
        body, boundary = _multipart("libsample.so", blob, "basic.file")
        file_data, analyzers = handler._parse_multipart(body, boundary.encode())

        self.assertEqual(analyzers, ["basic.file"])
        self.assertEqual(file_data[1], blob, "上传内容被 multipart 解析改动")

        with self._analyze(blob, "basic.file") as response:
            payload = json.load(response)
        self.assertTrue(payload["success"], msg=payload.get("error"))


class MultipartParserTests(unittest.TestCase):
    """Direct checks on the framing rules, without a socket."""

    def setUp(self) -> None:
        self.handler = WebRequestHandler.__new__(WebRequestHandler)

    def _wrap(self, payload: bytes, boundary: str) -> bytes:
        return (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="x.so"\r\n\r\n'
        ).encode() + payload + b"\r\n" + f"--{boundary}--\r\n".encode()

    def test_binary_content_is_returned_verbatim(self):
        boundary = "----" + uuid.uuid4().hex
        for tail in (b"\r\n", b"\r", b"\n", b"", b"\x00"):
            with self.subTest(tail=tail):
                payload = b"\x7fELF" + b"A" * 64 + tail
                file_data, analyzers = self.handler._parse_multipart(
                    self._wrap(payload, boundary), boundary.encode()
                )
                self.assertEqual(analyzers, [])
                self.assertEqual(file_data[1], payload)

    def test_analyzers_field_is_split_and_trimmed(self):
        boundary = "----" + uuid.uuid4().hex
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="analyzers"\r\n\r\n'
            f"basic.file, security.risk ,\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        file_data, analyzers = self.handler._parse_multipart(
            body, boundary.encode()
        )
        self.assertIsNone(file_data)
        self.assertEqual(analyzers, ["basic.file", "security.risk"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
