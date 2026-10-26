"""Integration tests for the web console background job endpoints.

The job endpoints stream a subprocess's stderr into a pollable log, then
expose the CLI JSON payload, so the tests drive a real analysis of a small
text target (valid non-ELF) and a synthetic ELF from tests.conftest.
"""

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from tests.conftest import build_elf64_with_symbols

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "soinsight_web_server", "web/server.py"
)
server_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server_module)


def _request(handler, base, method, data=None):
    return urllib.request.Request(base + handler, data=data, method=method)


class WebJobConsoleTests(unittest.TestCase):
    httpd: ThreadingHTTPServer
    base: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _start_job(self, body: bytes, filename: str) -> str:
        response = urllib.request.urlopen(
            urllib.request.Request(
                f"{self.base}/api/jobs",
                data=body,
                headers={"X-Filename": filename},
                method="POST",
            )
        )
        payload = json.load(response)
        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        return payload["job"]

    def _wait_done(self, job_id: str) -> dict:
        offset = 0
        collected: list[dict] = []
        for _ in range(240):
            response = urllib.request.urlopen(
                f"{self.base}/api/jobs/{job_id}/log?offset={offset}"
            )
            log = json.load(response)
            offset = log["offset"]
            collected.extend(log["lines"])
            if log["done"]:
                return {"lines": collected, "exit_code": log["exit_code"]}
            # The job spawns a real subprocess, which needs a few hundred ms to
            # start and import; polling without a pause burns through the
            # iteration budget before the job ever gets going.
            time.sleep(0.05)
        raise AssertionError("job did not finish within the harness timeout")

    def test_health_reports_registered_analyzers(self):
        response = urllib.request.urlopen(f"{self.base}/api/health")
        payload = json.load(response)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["registered_analyzers"]), 8)

    def _job_log_text(self, log: dict) -> str:
        return "\n".join(
            f"{line['t']} {line['text']}" for line in log["lines"]
        )

    def test_job_runs_full_scan_and_streams_log(self):
        body = b"password=hunter2-secret\x00https://api.example.com/login\x00A" * 32
        job_id = self._start_job(body, "sample.so")

        with self.assertRaises(urllib.error.HTTPError) as early:
            urllib.request.urlopen(f"{self.base}/api/jobs/{job_id}/result")
        self.assertEqual(early.exception.code, 409)

        log = self._wait_done(job_id)
        # A text target fails the ELF chain (exit 5) but is still a valid
        # result payload; only transport-level errors must stay absent.
        self.assertIn(
            log["exit_code"], (0, 5),
            msg="job log:\n" + self._job_log_text(log),
        )
        joined = self._job_log_text(log)
        self.assertIn("子进程已启动", joined)
        self.assertIn("running advanced.strings", joined)
        self.assertIn("结果 JSON 已生成", joined)

        result = json.load(urllib.request.urlopen(
            f"{self.base}/api/jobs/{job_id}/result"
        ))
        self.assertIsNone(result["error"])
        resolved = result["payload"]["result"]["resolved_analyzers"]
        self.assertIn("advanced.strings", resolved)
        self.assertIn("security.risk", resolved)
        rule_ids = [
            finding["rule_id"] for finding in result["payload"]["result"]["findings"]
        ]
        self.assertIn("security.sensitive-string.password-token", rule_ids)

    def test_job_from_elf_target_scores_risk(self):
        blob = build_elf64_with_symbols([("", 0, 3, 0xFFF1, 0, 0)], with_symtab=False)
        job_id = self._start_job(blob, "libsample.so")

        log = self._wait_done(job_id)
        self.assertEqual(
            log["exit_code"], 0,
            msg="job log:\n" + self._job_log_text(log),
        )

        result = json.load(urllib.request.urlopen(
            f"{self.base}/api/jobs/{job_id}/result"
        ))
        risk = result["payload"]["result"]["results"]["security.risk"]["data"]
        self.assertEqual(risk["risk_level"], "low")
        self.assertEqual(risk["risk_score"], 0)

    def test_result_of_unknown_job_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base}/api/jobs/" + "0" * 12 + "/result")
        self.assertEqual(ctx.exception.code, 404)



class WebAnalyzeMultiModeTests(unittest.TestCase):
    """``POST /api/analyze?mode=multi`` runs exactly the capabilities picked."""

    httpd: ThreadingHTTPServer
    base: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _analyze(self, query: str, body: bytes | None = None):
        request = urllib.request.Request(
            f"{self.base}/api/analyze?{query}", data=body, method="POST"
        )
        request.add_header("X-Filename", "libsample.so")
        return urllib.request.urlopen(request)

    def test_multi_runs_only_selected_capabilities(self):
        blob = build_elf64_with_symbols([("", 0, 3, 0xFFF1, 0, 0)], with_symtab=False)
        response = self._analyze("mode=multi&capabilities=basic.file,basic.elf", blob)
        self.assertEqual(response.status, 200)

        payload = json.load(response)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["exit_code"], 0)

        result = payload["payload"]["result"]
        self.assertEqual(sorted(result["resolved_analyzers"]), ["basic.elf", "basic.file"])
        self.assertEqual(sorted(result["results"]), ["basic.elf", "basic.file"])

    def test_multi_results_carry_text_output(self):
        blob = build_elf64_with_symbols([("", 0, 3, 0xFFF1, 0, 0)], with_symtab=False)
        payload = json.load(self._analyze("mode=multi&capabilities=basic.file,basic.elf", blob))

        for analyzer_id, entry in payload["payload"]["result"]["results"].items():
            self.assertTrue(entry["text"], f"{analyzer_id} 的 text 为空")
            self.assertTrue(
                entry["text"].startswith("==="),
                f"{analyzer_id} 的 text 不是预期的标题格式: {entry['text'][:40]!r}",
            )

    def test_multi_rejects_empty_capability_list(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._analyze("mode=multi&capabilities=", b"placeholder")
        self.assertEqual(ctx.exception.code, 400)
        body = json.load(ctx.exception)
        self.assertFalse(body["ok"])
        self.assertIn("capabilities", body["error"])

    def test_multi_rejects_unknown_capability(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._analyze("mode=multi&capabilities=basic.elf,bogus.thing", b"placeholder")
        self.assertEqual(ctx.exception.code, 400)
        body = json.load(ctx.exception)
        self.assertFalse(body["ok"])
        self.assertIn("bogus.thing", body["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
