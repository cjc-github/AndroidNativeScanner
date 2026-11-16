"""Integration tests for the web console's directory (batch) analysis.

The console accepted a single server path only, so a directory of libraries
could not be analyzed from the browser even though the CLI could. The server
now expands a directory the same way the CLI does -- with the same include
and exclude filters -- and returns one document per target plus a summary.
"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from tests.conftest import SAMPLE_SYMBOLS, build_elf64_with_symbols

from soinsight.web import console as server_module


def _isolate_db(cls):
    cls._db_tmp = tempfile.TemporaryDirectory()
    cls._db_patcher = mock.patch.object(
        server_module, "DB_PATH", Path(cls._db_tmp.name) / "test_web.db"
    )
    cls._db_patcher.start()


def _restore_db(cls):
    cls._db_patcher.stop()
    cls._db_tmp.cleanup()


class WebBatchAnalysisTests(unittest.TestCase):
    """The console analyzes a directory as a batch."""

    @classmethod
    def setUpClass(cls):
        _isolate_db(cls)
        cls._server = ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
        cls.base = f"http://127.0.0.1:{cls._server.server_address[1]}"
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._server.server_close()
        _restore_db(cls)

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _libraries(self) -> Path:
        """A directory with two libraries and one unrelated file."""
        libraries = self.tmp / "libs"
        libraries.mkdir()
        (libraries / "a.so").write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS))
        (libraries / "b.so").write_bytes(build_elf64_with_symbols(SAMPLE_SYMBOLS))
        (libraries / "notes.txt").write_text("not a library")
        return libraries

    def _analyze(self, query: str):
        request = urllib.request.Request(
            f"{self.base}/api/analyze?{query}", method="POST", data=b""
        )
        with urllib.request.urlopen(request) as response:
            return json.load(response)

    def test_a_directory_is_analyzed_as_a_batch(self):
        libraries = self._libraries()

        response = self._analyze(
            f"mode=multi&capabilities=basic.file&path={libraries}"
        )

        self.assertTrue(response["ok"])
        payload = response["payload"]
        self.assertEqual(payload["summary"]["target_count"], 3)
        self.assertEqual(payload["summary"]["completed_count"], 3)
        self.assertEqual(payload["summary"]["failed_count"], 0)
        # Every target produced its own document.
        self.assertEqual(len(payload["results"]), 3)

    def test_the_include_filter_narrows_the_batch(self):
        libraries = self._libraries()

        response = self._analyze(
            f"mode=multi&capabilities=basic.file&include=*.so&path={libraries}"
        )

        self.assertEqual(response["payload"]["summary"]["target_count"], 2)

    def test_the_exclude_filter_drops_files(self):
        libraries = self._libraries()

        response = self._analyze(
            f"mode=multi&capabilities=basic.file&include=*.so&exclude=b*&path={libraries}"
        )

        payload = response["payload"]
        self.assertEqual(payload["summary"]["target_count"], 1)
        for path in payload["results"]:
            self.assertTrue(path.endswith("a.so"))

    def test_a_single_file_still_works(self):
        libraries = self._libraries()

        response = self._analyze(
            f"mode=multi&capabilities=basic.file&path={libraries / 'a.so'}"
        )

        self.assertTrue(response["ok"])
        payload = response["payload"]
        # A single target keeps the original document shape.
        self.assertIn("result", payload)
        self.assertEqual(payload["result"]["status"], "success")

    def test_an_empty_directory_is_reported(self):
        empty = self.tmp / "empty"
        empty.mkdir()

        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._analyze(f"mode=multi&capabilities=basic.file&path={empty}")

        payload = json.loads(raised.exception.read().decode("utf-8"))
        self.assertFalse(payload["ok"])
        self.assertIn("没有可分析的文件", payload["error"])

    def test_a_missing_path_is_reported(self):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._analyze(
                f"mode=multi&capabilities=basic.file&path={self.tmp / 'nope.so'}"
            )

        payload = json.loads(raised.exception.read().decode("utf-8"))
        self.assertFalse(payload["ok"])
        self.assertIn("服务器路径无效", payload["error"])
