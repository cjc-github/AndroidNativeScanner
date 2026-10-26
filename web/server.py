#!/usr/bin/env python3
"""SOInsight Web 控制台 —— 本地分析服务器（仅标准库，无第三方依赖）。

浏览器页面本身无法直接执行本机的 Python 分析，所以本服务在 127.0.0.1 上启动一个
本地 HTTP 服务：页面通过它上传或指定 .so 目标文件，服务以子进程方式调用
``python -m soinsight <capability> <target> --format json``，再把结构化结果回传
给页面渲染。服务只绑定回环地址，不会把本机文件暴露到局域网。

用法::

    python site/server.py              # 启动并自动打开浏览器
    python site/server.py --no-open    # 只启动服务，不打开浏览器
    python site/server.py --port 9000  # 指定端口（默认 8765，占用则顺延）

API::

    GET  /api/health        服务与运行环境状态（版本、Python、已注册 Analyzer）
    GET  /api/modules       产品能力目录（42 项能力及各自实现状态）
    GET  /api/samples       in/ 目录下的验证样本列表（只读）
    POST /api/analyze      执行一次分析，查询参数：
                             mode=single&capability=basic.elf   单能力
                             mode=multi&capabilities=basic.elf,basic.symbols   多选能力
                             mode=scan&modules=basic,advanced,security   组合扫描
                             目标二选一：查询参数 path=<绝对路径>，
                             或请求体直接传文件字节并带 X-Filename 头。
                           返回 {ok, exit_code, command, duration_ms, payload}
    POST /api/jobs         创建一个后台深度扫描任务（目标同 /api/analyze）。
                           以 ``python -m soinsight scan <target> --format json``
                           默认全量能力运行，stderr 进度实时写日志。返回
                           {ok, job}。
    GET  /api/jobs/<id>/log?offset=N
                           增量日志：{ok, lines:[{t,text}], offset, done,
                           exit_code, duration_ms}。done=True 后可拉结果。
    GET  /api/jobs/<id>/result
                           任务完成后取完整 CLI JSON：{ok, exit_code,
                           duration_ms, command, payload}。
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SITE_DIR = Path(__file__).resolve().parent
REPO_ROOT = SITE_DIR.parent
SRC_DIR = REPO_ROOT / "src"
SAMPLES_DIR = REPO_ROOT / "in"

DEFAULT_PORT = 8765
MAX_UPLOAD_BYTES = 128 * 1024 * 1024
SAMPLE_SUFFIXES = {".so", ".elf", ".o", ".dylib"}

ANALYSIS_TIMEOUT = 180
_ANALYSIS_LOCK = threading.Lock()

MAX_JOBS_KEPT = 8
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()

# The catalog import needs the package on sys.path; the heavy imports happen
# lazily inside _load_catalog() so a broken environment fails one endpoint
# instead of the whole server.
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from soinsight.version import __version__  # noqa: E402

_STATE: dict[str, object] = {"catalog": None, "error": None, "analyzer_ids": []}


def _load_catalog() -> None:
    """Import the module catalog and analyzer registry once, in-process."""
    if _STATE["catalog"] is not None or _STATE["error"] is not None:
        return
    try:
        from soinsight.analyzers import register_builtin_analyzers
        from soinsight.core.analyzer import AnalyzerRegistry
        from soinsight.modules import create_builtin_module_catalog

        registry = AnalyzerRegistry()
        register_builtin_analyzers(registry)
        try:
            from soinsight.infrastructure.plugins import PluginLoader

            PluginLoader().load(registry)
        except Exception:
            pass

        modules = []
        for module in create_builtin_module_catalog().list():
            modules.append(
                {
                    "id": module.id,
                    "name": module.name,
                    "description": module.description,
                    "capabilities": [
                        {
                            "id": capability.id,
                            "command": capability.command,
                            "name": capability.name,
                            "description": capability.description,
                            "implemented": registry.contains(capability.id),
                        }
                        for capability in module.capabilities
                    ],
                }
            )
        _STATE["catalog"] = modules
        _STATE["analyzer_ids"] = sorted(item.id for item in registry.list())
    except Exception as exc:  # pragma: no cover - environment dependent
        _STATE["error"] = f"{type(exc).__name__}: {exc}"


def _known_capability_ids() -> set[str]:
    catalog = _STATE["catalog"] or []
    return {
        capability["id"]
        for module in catalog
        for capability in module["capabilities"]
    }


def _list_samples() -> list[dict]:
    if not SAMPLES_DIR.is_dir():
        return []
    samples = []
    for path in sorted(SAMPLES_DIR.iterdir()):
        if path.is_file() and path.suffix.lower() in SAMPLE_SUFFIXES:
            samples.append(
                {
                    "name": path.name,
                    "path": str(path.resolve()),
                    "size": path.stat().st_size,
                }
            )
    return samples


def _run_analysis(
    mode: str,
    capability: str,
    modules: str,
    target: Path,
    capabilities: tuple[str, ...] = (),
) -> dict:
    """Run one analysis in a subprocess and return the parsed JSON payload."""
    argv = [sys.executable, "-m", "soinsight"]
    if mode == "scan":
        argv += ["scan", str(target), "--module-available", modules]
    elif mode == "multi":
        argv += ["scan", str(target), "--enable", ",".join(capabilities)]
    else:
        argv += capability.split(".") + [str(target)]
    argv += ["--format", "json", "--no-cache", "--quiet"]

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(SRC_DIR), env.get("PYTHONPATH")) if part
    )
    env["PYTHONIOENCODING"] = "utf-8"

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=ANALYSIS_TIMEOUT,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"分析超时（超过 {ANALYSIS_TIMEOUT} 秒）",
            "command": argv,
            "exit_code": None,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "payload": None,
            "stderr_tail": "",
        }

    duration_ms = int((time.perf_counter() - started) * 1000)
    stdout = completed.stdout or ""
    payload = None
    parse_error = None
    try:
        payload = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError as exc:
        parse_error = f"CLI 输出不是有效 JSON: {exc}"
    if payload is None and parse_error is None:
        stderr_text = completed.stderr or ""
        if "ModuleNotFoundError" in stderr_text:
            parse_error = (
                "分析子进程缺少依赖（子进程使用 "
                f"{sys.executable}）。请用安装了项目依赖的 Python 运行本服务，"
                "例如项目虚拟环境：.venv\\Scripts\\python site\\server.py"
            )
        else:
            parse_error = f"CLI 未产生 JSON 输出（退出码 {completed.returncode}）"
    return {
        # A non-zero exit code with a valid payload is still a real analysis
        # result (e.g. an analyzer reporting FAILED); the page renders it.
        "ok": payload is not None,
        "error": parse_error,
        "command": argv,
        "exit_code": completed.returncode,
        "duration_ms": duration_ms,
        "payload": payload,
        "stdout_tail": stdout[-4000:] if parse_error else "",
        "stderr_tail": (completed.stderr or "")[-2000:],
    }


def _now_stamp() -> str:
    return time.strftime("%H:%M:%S")


def _job_log(job: dict, text: str) -> None:
    with _JOBS_LOCK:
        job["lines"].append({"t": _now_stamp(), "text": text})


def _prune_jobs() -> None:
    with _JOBS_LOCK:
        overflow = len(_JOBS) - MAX_JOBS_KEPT
        if overflow > 0:
            oldest = sorted(_JOBS, key=lambda key: _JOBS[key]["started"])[:overflow]
            for key in oldest:
                _JOBS.pop(key, None)


def _finish_job(job: dict, **fields: object) -> None:
    with _JOBS_LOCK:
        job.update(fields)
        job["done"] = True


def _write_upload(body: bytes, filename: str) -> Path:
    """Persist one uploaded target to a private temp file and return it."""
    suffix = Path(os.path.basename(filename)).suffix
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix):
        suffix = ".so"
    handle, temp_path = tempfile.mkstemp(prefix="soinsight-upload-", suffix=suffix)
    with os.fdopen(handle, "wb") as stream:
        stream.write(body)
    return Path(temp_path)


def _transform_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(SRC_DIR), env.get("PYTHONPATH")) if part
    )
    env["PYTHONIOENCODING"] = "utf-8"
    # Ensure HOME is set for Path.home() to work in subprocess
    if "HOME" not in env and "USERPROFILE" in env:
        env["HOME"] = env["USERPROFILE"]
    return env


def _start_job(target: Path, display_name: str, cleanup: bool = False) -> dict:
    """Create a background full scan job and return its tracking record."""
    job_id = uuid.uuid4().hex[:12]
    argv = [sys.executable, "-m", "soinsight", "scan", str(target)]
    argv += ["--format", "json", "--no-cache"]
    job = {
        "id": job_id,
        "filename": display_name,
        "target": str(target),
        "cleanup_target": cleanup,
        "lines": [],
        "started": time.time(),
        "done": False,
        "exit_code": None,
        "duration_ms": None,
        "payload": None,
        "error": None,
        "command": argv,
    }
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    _prune_jobs()
    threading.Thread(
        target=_job_worker, args=(job, target), daemon=True, name=f"soinsight-job-{job_id}"
    ).start()
    return job


def _job_worker(job: dict, target: Path) -> None:
    """Run the CLI scan in the background, streaming stderr into the job log.

    stdout stays on its own pump thread so a hung child process hits the
    overall deadline instead of blocking the worker on ``stdout.read()``.
    """
    started = time.perf_counter()
    try:
        _job_log(job, f"目标: {target.name}（{target.stat().st_size} 字节）")
    except OSError as exc:
        _finish_job(job, error=f"目标文件不可读: {exc}")
        return
    if not _ANALYSIS_LOCK.acquire(timeout=10):
        _finish_job(job, error="已有分析在占用执行槽位，且等待超时")
        return
    process = None
    try:
        process = subprocess.Popen(
            job["command"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_transform_env(),
            cwd=str(REPO_ROOT),
        )
        _job_log(job, "子进程已启动，实时进度如下")

        stdout_chunks: list[str] = []

        def _pump_streams(stream, sink) -> None:
            for line in stream:
                text = line.rstrip()
                if text:
                    sink(text)

        pump_out = threading.Thread(
            target=_pump_streams, args=(process.stdout, stdout_chunks.append),
            daemon=True,
        )
        pump_out.start()
        pump_err = threading.Thread(
            target=_pump_streams, args=(process.stderr, lambda text: _job_log(job, text)),
            daemon=True,
        )
        pump_err.start()

        deadline = started + max(5.0, ANALYSIS_TIMEOUT)
        while True:
            if process.poll() is not None:
                break
            if time.perf_counter() > deadline:
                process.kill()
                process.wait(timeout=30)
                _job_log(job, f"分析超时（> {ANALYSIS_TIMEOUT}s），子进程已终止")
                _finish_job(
                    job,
                    error=f"分析超时（超过 {ANALYSIS_TIMEOUT} 秒）",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
                return
            pump_out.join(timeout=0.5)
            pump_err.join(timeout=0.0)

        pump_out.join(timeout=30)
        pump_err.join(timeout=30)
        wait_seconds = ANALYSIS_TIMEOUT - (time.perf_counter() - started)
        process.wait(timeout=max(1.0, wait_seconds))
        exit_code = process.returncode
        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout_text = "".join(stdout_chunks)
        _job_log(job, f"分析结束（exit_code={exit_code}，用时 {duration_ms} ms）")

        parse_error = None
        try:
            payload = json.loads(stdout_text) if stdout_text.strip() else None
        except json.JSONDecodeError as exc:
            payload, parse_error = None, f"CLI 输出不是有效 JSON: {exc}"

        if payload is None:
            _job_log(job, f"错误: {parse_error or 'CLI 未产生 JSON 输出'}")
            _finish_job(
                job,
                exit_code=exit_code,
                duration_ms=duration_ms,
                error=parse_error or f"CLI 未产生 JSON 输出（退出码 {exit_code}）",
            )
            return

        _job_log(
            job,
            f"结果 JSON 已生成（{len(json.dumps(payload, ensure_ascii=False)) // 1024} KB），在结果面板中查看",
        )
        envelope_diagnostics = payload.get("diagnostics") if isinstance(payload, dict) else None
        for diagnostic in (envelope_diagnostics or [])[:3]:
            _job_log(
                job,
                f"CLI 诊断: [{diagnostic.get('code')}] {diagnostic.get('message')}",
            )
        _finish_job(job, exit_code=exit_code, duration_ms=duration_ms, payload=payload)
    except Exception as exc:  # pragma: no cover - 环境相关的兜底
        _job_log(job, f"内部错误: {type(exc).__name__}: {exc}")
        _finish_job(job, error=f"任务执行失败: {type(exc).__name__}: {exc}")
    finally:
        if process is not None:
            for stream_obj in (process.stdout, process.stderr):
                try:
                    stream_obj.close()
                except OSError:
                    pass
        _ANALYSIS_LOCK.release()
        if job.get("cleanup_target"):
            try:
                target.unlink()
            except OSError:
                pass


CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".md": "text/plain; charset=utf-8",
}

_JOB_LOG_ROUTE = re.compile(r"/api/jobs/([0-9a-f]{12})/log")
_JOB_RESULT_ROUTE = re.compile(r"/api/jobs/([0-9a-f]{12})/result")


def _safe_int(value: str | None) -> tuple[int, bool]:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0, True
    return max(0, parsed), False


def _job_log_payload(job_id: str, offset: int) -> dict | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        lines = [dict(item) for item in job["lines"][offset:]]
        return {
            "ok": True,
            "job": job_id,
            "filename": job["filename"],
            "started": job["started"],
            "lines": lines,
            "offset": offset + len(lines),
            "done": job["done"],
            "exit_code": job["exit_code"],
            "duration_ms": job["duration_ms"],
            "error": job["error"],
        }


def _job_result_record(job_id: str) -> dict | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        return {
            "ok": True,
            "job": job_id,
            "filename": job["filename"],
            "target": job["target"],
            "started": job["started"],
            "done": job["done"],
            "exit_code": job["exit_code"],
            "duration_ms": job["duration_ms"],
            "command": job["command"],
            "error": job["error"],
            "payload": job["payload"],
        }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"SOInsightWeb/{__version__}"

    def log_message(self, fmt, *args):  # noqa: N802 - stdlib name
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers ---------------------------------------------------------
    def _send_json(self, obj: object, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, route: str) -> None:
        relative = route.lstrip("/") or "index.html"
        target = (SITE_DIR / relative).resolve()
        if SITE_DIR != target and SITE_DIR not in target.parents:
            self._send_json({"ok": False, "error": "禁止访问"}, HTTPStatus.FORBIDDEN)
            return
        if not target.is_file():
            self._send_json(
                {"ok": False, "error": f"文件不存在: {route}"}, HTTPStatus.NOT_FOUND
            )
            return
        self._send_bytes(
            target.read_bytes(),
            CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream"),
        )

    # -- routes ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        parsed = urlparse(self.path)
        route = parsed.path
        if route in ("/", "/index.html"):
            self._serve_static("/index.html")
        elif route == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif route == "/api/health":
            self._send_json(self._health_payload())
        elif route == "/api/modules":
            _load_catalog()
            if _STATE["error"]:
                self._send_json(
                    {"ok": False, "error": _STATE["error"]},
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return
            self._send_json({"ok": True, "modules": _STATE["catalog"]})
        elif route == "/api/samples":
            self._send_json({"ok": True, "samples": _list_samples()})
        elif _JOB_LOG_ROUTE.fullmatch(route):
            params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
            offset, parse_failed = _safe_int(params.get("offset"))
            if parse_failed:
                self._send_json(
                    {"ok": False, "error": "offset 必须是非负整数"},
                    HTTPStatus.BAD_REQUEST,
                )
                return
            payload = _job_log_payload(_JOB_LOG_ROUTE.fullmatch(route).group(1), offset)
            if payload is None:
                self._send_json(
                    {"ok": False, "error": "任务不存在或已被清理"},
                    HTTPStatus.NOT_FOUND,
                )
                return
            self._send_json(payload)
        elif _JOB_RESULT_ROUTE.fullmatch(route):
            record = _job_result_record(_JOB_RESULT_ROUTE.fullmatch(route).group(1))
            if record is None:
                self._send_json(
                    {"ok": False, "error": "任务不存在或已被清理"},
                    HTTPStatus.NOT_FOUND,
                )
                return
            if not record["done"]:
                self._send_json(
                    {"ok": False, "error": "任务尚未结束，继续轮询 /log"},
                    HTTPStatus.CONFLICT,
                )
                return
            self._send_json(record)
        else:
            self._serve_static(route)

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        parsed = urlparse(self.path)
        if parsed.path not in ("/api/analyze", "/api/jobs"):
            self._send_json(
                {"ok": False, "error": f"未知路径: {parsed.path}"},
                HTTPStatus.NOT_FOUND,
            )
            return

        params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        is_job = parsed.path == "/api/jobs"
        mode = params.get("mode", "scan" if is_job else "single")
        capability = params.get("capability", "").strip()
        capabilities = tuple(
            item.strip()
            for item in params.get("capabilities", "").split(",")
            if item.strip()
        )
        modules = params.get(
            "modules", ""
        ).strip() or "basic,advanced,security"
        path_param = params.get("path", "").strip()

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD_BYTES:
            self._send_json(
                {"ok": False, "error": f"文件超过 {MAX_UPLOAD_BYTES // 1048576} MiB 上限"},
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return
        body = self.rfile.read(length) if length else b""

        temp_path: str | None = None
        try:
            target: Path
            if path_param:
                candidate = Path(path_param)
                if not candidate.is_absolute() or not candidate.is_file():
                    self._send_json(
                        {"ok": False, "error": f"服务器路径无效: {path_param}"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                target = candidate
            else:
                if not body:
                    self._send_json(
                        {"ok": False, "error": "请求体为空：既没有 path 参数，也没有上传文件"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                filename = os.path.basename(
                    self.headers.get("X-Filename") or "upload.so"
                )
                suffix = Path(filename).suffix
                if not re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix):
                    suffix = ".so"
                handle, temp_path = tempfile.mkstemp(
                    prefix="soinsight-upload-", suffix=suffix
                )
                with os.fdopen(handle, "wb") as stream:
                    stream.write(body)
                target = Path(temp_path)

            if not is_job and mode not in ("single", "scan", "multi"):
                self._send_json(
                    {"ok": False, "error": f"未知 mode: {mode}"},
                    HTTPStatus.BAD_REQUEST,
                )
                return
            if not is_job and mode == "single":
                _load_catalog()
                known = _known_capability_ids()
                if capability not in known:
                    self._send_json(
                        {
                            "ok": False,
                            "error": f"未知能力: {capability or '(空)'}，可用: "
                            + ", ".join(sorted(known)),
                        },
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
            if not is_job and mode == "multi":
                _load_catalog()
                known = _known_capability_ids()
                if not capabilities:
                    self._send_json(
                        {"ok": False, "error": "mode=multi 需要至少一个 capabilities"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                unknown = [item for item in capabilities if item not in known]
                if unknown:
                    self._send_json(
                        {
                            "ok": False,
                            "error": "未知能力: " + ", ".join(unknown)
                            + "，可用: " + ", ".join(sorted(known)),
                        },
                        HTTPStatus.BAD_REQUEST,
                    )
                    return

            if is_job:
                _load_catalog()
                if _STATE["error"]:
                    self._send_json(
                        {"ok": False, "error": _STATE["error"]},
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                    return
                record = _start_job(target, target.name, cleanup=not path_param)
                self._send_json(
                    {
                        "ok": True,
                        "job": record["id"],
                        "filename": record["filename"],
                        "note": "轮询 /api/jobs/<id>/log 直到 done=True，再取 /api/jobs/<id>/result",
                    }
                )
                return

            if not _ANALYSIS_LOCK.acquire(timeout=5):
                self._send_json(
                    {"ok": False, "error": "已有分析在进行中，请稍候重试"},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return
            try:
                result = _run_analysis(mode, capability, modules, target, capabilities)
            finally:
                _ANALYSIS_LOCK.release()
            self._send_json(result)
        finally:
            # Job uploads are owned by the background worker: it unlinks the
            # temp target after the child process has finished with it.
            if temp_path and not is_job:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _health_payload(self) -> dict:
        _load_catalog()
        catalog = _STATE["catalog"] or []
        return {
            "ok": _STATE["error"] is None,
            "version": __version__,
            "python": platform.python_version(),
            "python_executable": sys.executable,
            "platform": platform.platform(),
            "repo_root": str(REPO_ROOT),
            "product_modules": len(catalog),
            "registered_analyzers": _STATE["analyzer_ids"],
            "catalog_error": _STATE["error"],
            "analysis_timeout_seconds": ANALYSIS_TIMEOUT,
        }


def main(argv: list[str] | None = None) -> int:
    global ANALYSIS_TIMEOUT

    parser = argparse.ArgumentParser(
        description="SOInsight Web 控制台本地服务器（默认只绑定 127.0.0.1）"
    )
    parser.add_argument("--host", default="127.0.0.1", help="绑定地址（默认 127.0.0.1；检测到 PORT 环境变量时自动改为 0.0.0.0）")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="起始端口（默认 8765；被 PORT 环境变量覆盖）")
    parser.add_argument("--timeout", type=int, default=180, help="单次分析超时秒数（默认 180）")
    parser.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args(argv)
    ANALYSIS_TIMEOUT = max(10, args.timeout)

    # Cloud deploy injects PORT and expects a public bind on 0.0.0.0; locally we
    # keep the loopback-only default so the server never exposes the host.
    host = args.host
    env_port = os.environ.get("PORT")
    if env_port:
        port = int(env_port)
        if host == "127.0.0.1":
            host = "0.0.0.0"
    else:
        port = args.port

    _load_catalog()
    if _STATE["error"]:
        print(f"警告: 产品目录加载失败（{_STATE['error']}）")
        print("请确认当前 Python 能 import soinsight（需要 PyYAML，且 src/ 存在）。")

    server = None
    for p in range(port, port + 20):
        try:
            server = ThreadingHTTPServer((host, p), Handler)
            break
        except OSError:
            continue
    if server is None:
        print(f"错误: 端口 {port}-{port + 19} 均被占用，请用 --port 换一个。")
        return 1
    server.daemon_threads = True

    url = f"http://{host}:{server.server_address[1]}"
    analyzer_count = len(_STATE["analyzer_ids"])
    print("SOInsight Web 控制台")
    print(f"  版本        {__version__}")
    print(f"  项目目录    {REPO_ROOT}")
    print(f"  Python      {platform.python_version()} ({sys.executable})")
    print(f"  已注册能力  {analyzer_count} 个 Analyzer")
    print(f"  地址        {url}")
    bind_note = f"绑定 0.0.0.0（云端 PORT={env_port}）" if env_port else "仅绑定 127.0.0.1"
    print(f"  说明        {bind_note}；停止服务请按 Ctrl+C")
    print()

    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
