"""Regression tests for the shipped web console.

The console was rewritten twice: first as a small in-process server inside
the package, then as the full console in ``web/server.py``. The package now
ships that console, so these tests exercise it directly.

The defects covered here were both observed in the shipped code:

* the analysis runner passed ``target`` as a plain ``str`` even though
  ``AnalysisRequest.target`` is typed ``Path``; ``TargetResolver.resolve()``
  calls ``Path``-only methods, so every upload failed with
  ``'str' object has no attribute 'expanduser'`` (HTTP 500);
* the server was serial, so one in-flight analysis stopped it from
  answering even ``/api/health``.

The console runs analyses in a subprocess, so the tests upload a small
synthetic ELF built from ``tests.conftest``.
"""

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from tests.conftest import build_elf64_with_symbols

from soinsight.web import console


def _upload_request(
    base: str,
    payload: bytes,
    analyzers: str | None = None,
) -> urllib.request.Request:
    """A request that uploads the file bytes directly.

    The console takes the file as the request body and names it with the
    ``X-Filename`` header; the selected capabilities travel in the query.
    """
    query = "mode=multi"
    if analyzers:
        query += f"&capabilities={analyzers}"
    return urllib.request.Request(
        f"{base}/api/analyze?{query}",
        data=payload,
        headers={"X-Filename": "libsample.so"},
        method="POST",
    )


class WebConsoleTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _analyze(self, payload: bytes, analyzers: str | None = None):
        request = _upload_request(self.base, payload, analyzers)
        with urllib.request.urlopen(request, timeout=180) as response:
            return json.load(response)

    def test_an_uploaded_file_is_analyzed(self):
        blob = build_elf64_with_symbols([])

        response = self._analyze(blob, "basic.file")

        self.assertTrue(response["ok"], response.get("error"))
        payload = response["payload"]
        self.assertEqual(payload["result"]["status"], "success")
        # The upload reached the analyzer unchanged: a body that the
        # multipart framing had altered would show a different size.
        result = payload["result"]["results"]["basic.file"]["data"]
        self.assertEqual(result["size"], len(blob))

    def test_the_console_answers_while_an_analysis_runs(self):
        """A serial server would block the health check during an analysis."""
        blob = build_elf64_with_symbols([])
        request = _upload_request(self.base, blob, "basic.file")

        def _run() -> None:
            try:
                urllib.request.urlopen(request, timeout=180).read()
            except Exception:
                pass

        worker = threading.Thread(target=_run, daemon=True)
        worker.start()

        # The server must answer while the analysis is in flight.
        deadline = time.time() + 20
        answered = False
        while time.time() < deadline and not answered:
            try:
                with urllib.request.urlopen(
                    f"{self.base}/api/health", timeout=5
                ) as response:
                    answered = response.status == 200
            except Exception:
                time.sleep(0.1)
        worker.join(timeout=30)

        self.assertTrue(answered, "the server did not answer during an analysis")

    def test_the_health_endpoint_lists_the_registered_analyzers(self):
        with urllib.request.urlopen(f"{self.base}/api/health", timeout=10) as response:
            payload = json.load(response)

        self.assertTrue(payload["ok"])
        # The list comes from the registry, so it cannot hide an analyzer.
        # The count itself grows with the product, so it is not written down.
        self.assertGreater(len(payload["registered_analyzers"]), 0)
        self.assertIn("basic.file", payload["registered_analyzers"])

    def test_the_console_serves_its_page(self):
        with urllib.request.urlopen(f"{self.base}/", timeout=10) as response:
            body = response.read().decode("utf-8")

        self.assertIn("SOInsight", body)

    def test_an_unknown_path_is_reported(self):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(f"{self.base}/api/nothing", timeout=10)

        self.assertEqual(raised.exception.code, 404)