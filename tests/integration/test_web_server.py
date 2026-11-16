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
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.conftest import build_elf64_with_symbols

from soinsight.web import console


def _isolate_db(cls):
    cls._db_tmp = tempfile.TemporaryDirectory()
    cls._db_patcher = mock.patch.object(
        console, "DB_PATH", Path(cls._db_tmp.name) / "test_web.db"
    )
    cls._db_patcher.start()


def _restore_db(cls):
    cls._db_patcher.stop()
    cls._db_tmp.cleanup()


def _upload_request(
    base: str,
    payload: bytes,
    analyzers: str | None = None,
    project_id: int | None = None,
    task_name: str | None = None,
    task_description: str | None = None,
) -> urllib.request.Request:
    """A request that uploads the file bytes directly.

    The console takes the file as the request body and names it with the
    ``X-Filename`` header; the selected capabilities travel in the query.
    """
    query = "mode=multi"
    if analyzers:
        query += f"&capabilities={analyzers}"
    if project_id is not None:
        query += f"&project_id={project_id}"
    if task_name:
        query += "&task_name=" + urllib.parse.quote(task_name)
    if task_description:
        query += "&task_description=" + urllib.parse.quote(task_description)
    return urllib.request.Request(
        f"{base}/api/analyze?{query}",
        data=payload,
        headers={"X-Filename": "libsample.so"},
        method="POST",
    )


class WebConsoleTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        _isolate_db(cls)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        _restore_db(cls)

    def _analyze(
        self,
        payload: bytes,
        analyzers: str | None = None,
        project_id: int | None = None,
        task_name: str | None = None,
        task_description: str | None = None,
    ):
        request = _upload_request(
            self.base, payload, analyzers, project_id=project_id, task_name=task_name,
            task_description=task_description,
        )
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

    def _create_project(self, name: str = "Demo") -> dict:
        request = urllib.request.Request(
            f"{self.base}/api/projects?name=" + urllib.parse.quote(name),
            data=b"",
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
        self.assertTrue(payload["ok"], payload.get("error"))
        return payload["project"]

    def test_project_and_task_are_persisted_to_sqlite(self):
        blob = build_elf64_with_symbols([])
        project = self._create_project("回归项目")

        response = self._analyze(
            blob,
            "basic.file",
            project_id=project["id"],
            task_name="第一个任务",
        )

        self.assertTrue(response["ok"], response.get("error"))
        self.assertIn("task", response)
        task = response["task"]
        self.assertEqual(task["project_id"], project["id"])
        self.assertEqual(task["name"], "第一个任务")
        self.assertGreaterEqual(task["analyzer_count"], 1)

        with urllib.request.urlopen(f"{self.base}/api/projects", timeout=10) as res:
            projects = json.load(res)["projects"]
        self.assertTrue(any(p["id"] == project["id"] and p["task_count"] >= 1 for p in projects))

        with urllib.request.urlopen(f"{self.base}/api/tasks", timeout=10) as res:
            tasks = json.load(res)["tasks"]
        self.assertTrue(any(t["id"] == task["id"] for t in tasks))

        with urllib.request.urlopen(f"{self.base}/api/tasks/{task['id']}", timeout=10) as res:
            detail = json.load(res)["task"]
        self.assertTrue(detail["result"]["ok"])
        self.assertEqual(detail["result"]["payload"]["result"]["results"]["basic.file"]["data"]["size"], len(blob))

    def test_task_description_is_persisted_and_editable(self):
        blob = build_elf64_with_symbols([])
        project = self._create_project("描述项目")

        response = self._analyze(
            blob,
            "basic.file",
            project_id=project["id"],
            task_name="带描述任务",
            task_description="验证任务描述落库",
        )
        self.assertTrue(response["ok"], response.get("error"))
        self.assertEqual(response["task"]["description"], "验证任务描述落库")

        # PATCH /api/tasks/<id>：任务名称与描述都可编辑
        request = urllib.request.Request(
            f"{self.base}/api/tasks/{response['task']['id']}"
            + "?name=" + urllib.parse.quote("改名任务")
            + "&description=" + urllib.parse.quote("编辑后的描述"),
            data=b"",
            method="PATCH",
        )
        with urllib.request.urlopen(request, timeout=10) as res:
            payload = json.load(res)
        self.assertTrue(payload["ok"], payload.get("error"))
        self.assertEqual(payload["task"]["name"], "改名任务")
        self.assertEqual(payload["task"]["description"], "编辑后的描述")

        # 只传 name 不动 description（缺省参数 = 保持原样）
        request = urllib.request.Request(
            f"{self.base}/api/tasks/{response['task']['id']}"
            + "?name=" + urllib.parse.quote("再次改名"),
            data=b"",
            method="PATCH",
        )
        with urllib.request.urlopen(request, timeout=10) as res:
            payload = json.load(res)
        self.assertEqual(payload["task"]["name"], "再次改名")
        self.assertEqual(payload["task"]["description"], "编辑后的描述")

    def test_project_can_be_renamed_and_redescribed(self):
        project = self._create_project("旧名")

        request = urllib.request.Request(
            f"{self.base}/api/projects/{project['id']}"
            + "?name=" + urllib.parse.quote("新名")
            + "&description=" + urllib.parse.quote("新描述"),
            data=b"",
            method="PATCH",
        )
        with urllib.request.urlopen(request, timeout=10) as res:
            payload = json.load(res)
        self.assertTrue(payload["ok"], payload.get("error"))
        self.assertEqual(payload["project"]["name"], "新名")
        self.assertEqual(payload["project"]["description"], "新描述")

        # 项目不存在时返回 404
        request = urllib.request.Request(
            f"{self.base}/api/projects/999999?name=x", data=b"", method="PATCH"
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(raised.exception.code, 404)

    def test_project_can_be_deleted_with_its_tasks(self):
        blob = build_elf64_with_symbols([])
        project = self._create_project("待删除项目")
        self._analyze(blob, "basic.file", project_id=project["id"], task_name="子任务")

        request = urllib.request.Request(
            f"{self.base}/api/projects/{project['id']}", data=b"", method="DELETE"
        )
        with urllib.request.urlopen(request, timeout=10) as res:
            payload = json.load(res)
        self.assertTrue(payload["ok"])

        with urllib.request.urlopen(f"{self.base}/api/projects", timeout=10) as res:
            projects = json.load(res)["projects"]
        self.assertFalse(any(p["id"] == project["id"] for p in projects))

    def test_analyze_rejects_unknown_project(self):
        blob = build_elf64_with_symbols([])
        request = _upload_request(self.base, blob, "basic.file", project_id=999999)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=30)
        self.assertEqual(raised.exception.code, 400)
        payload = json.loads(raised.exception.read().decode("utf-8"))
        self.assertIn("项目不存在", payload["error"])

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
