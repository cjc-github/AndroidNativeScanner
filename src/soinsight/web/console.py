#!/usr/bin/env python3
"""SOInsight Web 控制台 —— 本地分析服务器（仅标准库，无第三方依赖）。

浏览器页面本身无法直接执行本机的 Python 分析，所以本服务在 127.0.0.1 上启动一个
本地 HTTP 服务：页面通过它上传或指定 .so 目标文件，服务以子进程方式调用
``python -m soinsight <capability> <target> --format json``，再把结构化结果回传
给页面渲染。服务只绑定回环地址，不会把本机文件暴露到局域网。

用法::

    python web/server.py              # 启动并自动打开浏览器
    python web/server.py --no-open    # 只启动服务，不打开浏览器
    python web/server.py --port 9000  # 指定端口（默认 8765，占用则顺延）

Windows 上推荐 ``py -3 web\\server.py``：若默认的 ``python`` 指向未安装
PyYAML 的解释器，产品目录会加载失败。Windows 用户也可直接双击
``web\\start-web.bat``。

API::

    GET  /api/health        服务与运行环境状态（版本、Python、已注册 Analyzer）
    GET  /api/modules       产品能力目录（42 项能力及各自实现状态）
    GET  /api/samples       in/ 目录下的验证样本列表（只读）
    GET  /api/presets       预置分析脚本列表（.soinsight/presets/*.json）
    POST /api/presets       保存一个预置分析脚本：?name=xxx&mode=multi|scan
                             &capabilities=basic.elf,basic.symbols
    DELETE /api/presets/<id>  删除一个预置分析脚本
    GET  /api/projects      项目列表（含每个项目的任务数）
    POST /api/projects      创建项目：?name=xxx&description=xxx
    DELETE /api/projects/<id>  删除项目及其全部任务
    GET  /api/tasks         全量任务列表（跨项目）
    GET  /api/projects/<id>/tasks  某项目下的任务列表
    GET  /api/tasks/<id>    任务详情（含完整分析结果 result）
    DELETE /api/tasks/<id>  删除单个任务
    POST /api/analyze      执行一次分析，查询参数：
                             mode=single&capability=basic.elf   单能力
                             mode=multi&capabilities=basic.elf,basic.symbols   多选能力
                             mode=scan&modules=basic,advanced,security   组合扫描
                             project_id=<id>&task_name=任务名   可选，指定后结果写入 SQLite
                             目标二选一：查询参数 path=<绝对路径>，
                             或请求体直接传文件字节并带 X-Filename 头。
                           返回 {ok, exit_code, command, duration_ms, payload,
                           task?}（task 为数据库中的任务记录）
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
    POST /api/cancel       终止正在运行的 /api/analyze 子进程，返回
                           {ok, cancelled}；没有在跑的任务时 cancelled=false。
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import json
import os
import platform
import re
import sqlite3
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
# The console ships inside the package (``src/soinsight/web``), so the
# repository root is three levels up. When the same file is run from a
# checkout (``web/server.py``) the root is one level up. Both are supported,
# so the script and the package never drift apart.
def _repository_root(site_dir: Path) -> Path:
    """The project root, whichever layout the console is loaded from."""
    for candidate in (site_dir.parent.parent.parent, site_dir.parent, site_dir):
        if (candidate / "src" / "soinsight").is_dir():
            return candidate
    return site_dir.parent.parent.parent


REPO_ROOT = _repository_root(SITE_DIR)
SRC_DIR = REPO_ROOT / "src"
SAMPLES_DIR = REPO_ROOT / "in"

DEFAULT_PORT = 8765
MAX_UPLOAD_BYTES = 128 * 1024 * 1024
# Streaming body read: never block a thread longer than this waiting for bytes
# a client advertised but is not sending (keeps one worker free per request).
_BODY_READ_TIMEOUT = 60.0
_BODY_READ_CHUNK = 1 << 20
SAMPLE_SUFFIXES = {".so", ".elf", ".o", ".dylib"}

ANALYSIS_TIMEOUT = 180
_ANALYSIS_LOCK = threading.Lock()

# 分析结果的落盘目录。full-scan 的 JSON 可达数 MB，整块回传给浏览器再由
# 前端渲染既慢又卡，所以服务端写盘、只把路径回给页面。
REPORTS_DIR = REPO_ROOT / "reports"
MAX_REPORTS_KEPT = 20
# 同一秒内并发落盘时最多尝试的序号数，超过即放弃（防御性上限，正常远达不到）
MAX_REPORT_SERIAL_TRIES = 1000
_REPORTS_LOCK = threading.Lock()

# 项目和任务的持久化：SQLite 单文件数据库。可由 SOINSIGHT_WEB_DB 环境变量覆盖
# （测试用临时库），默认为 .soinsight/web.db（.soinsight/ 已在 .gitignore 中）。
DB_PATH = Path(os.environ.get("SOINSIGHT_WEB_DB") or (REPO_ROOT / ".soinsight" / "web.db"))

# 预置分析脚本：把一组勾选的分析项（外加组合扫描开关）存成一个 JSON 文件，
# 下次在「分析能力」里选中该文件即可一次性套用。同样支持环境变量覆盖（测试用）。
PRESETS_DIR = Path(
    os.environ.get("SOINSIGHT_WEB_PRESETS") or (REPO_ROOT / ".soinsight" / "presets")
)
MAX_PRESETS_KEPT = 200
_PRESET_NAME_RE = re.compile(r"^[\w][\w .\-]{0,59}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'success',
    target_name TEXT NOT NULL DEFAULT '',
    target_path TEXT NOT NULL DEFAULT '',
    target_sha256 TEXT,
    target_size INTEGER,
    mode TEXT NOT NULL DEFAULT 'multi',
    capabilities TEXT NOT NULL DEFAULT '[]',
    modules TEXT NOT NULL DEFAULT '',
    command TEXT,
    exit_code INTEGER,
    duration_ms INTEGER,
    analyzer_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at);
"""

@contextlib.contextmanager
def _db_conn():
    """Open a short-lived SQLite connection and initialise the schema."""
    path = Path(DB_PATH)
    if str(path).startswith("~"):
        path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(_SCHEMA)
        _migrate_schema(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


# 早期版本建库时 tasks 表还没有 description 列（任务描述）。
# CREATE TABLE IF NOT EXISTS 不会给已存在的表补列，所以单独做一次轻量迁移。
_MIGRATIONS = (("tasks", "description", "TEXT NOT NULL DEFAULT ''"),)


def _migrate_schema(conn) -> None:
    for table, column, spec in _MIGRATIONS:
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {spec}")


def _json_list(value: str | None) -> list:
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def _project_dict(conn, row) -> dict:
    task_count = row["task_count"] if "task_count" in row.keys() else conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE project_id = ?", (row["id"],)
    ).fetchone()[0]
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "task_count": task_count,
    }


def _create_project(name: str, description: str = "") -> dict | None:
    now = time.time()
    with _db_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO projects(name, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (name, description, now, now),
        )
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        return _project_dict(conn, row)


def _list_projects() -> list[dict]:
    with _db_conn() as conn:
        rows = conn.execute(
            """
            SELECT p.*, (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count
            FROM projects p ORDER BY p.created_at DESC, p.id DESC
            """
        ).fetchall()
        return [_project_dict(conn, row) for row in rows]


def _get_project(project_id: int) -> dict | None:
    with _db_conn() as conn:
        row = conn.execute(
            """
            SELECT p.*, (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count
            FROM projects p WHERE p.id = ?
            """, (project_id,)
        ).fetchone()
        return _project_dict(conn, row) if row else None


def _delete_project(project_id: int) -> bool:
    with _db_conn() as conn:
        cursor = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        return cursor.rowcount > 0


def _update_project(project_id: int, name: str | None, description: str | None) -> dict | None:
    """Update a project's name and/or description. ``None`` means "leave as is"."""
    with _db_conn() as conn:
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if row is None:
            return None
        new_name = row["name"] if name is None else name.strip() or row["name"]
        new_desc = row["description"] if description is None else description.strip()
        conn.execute(
            "UPDATE projects SET name = ?, description = ?, updated_at = ? WHERE id = ?",
            (new_name, new_desc, time.time(), project_id),
        )
        row = conn.execute(
            """
            SELECT p.*, (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count
            FROM projects p WHERE p.id = ?
            """,
            (project_id,),
        ).fetchone()
        return _project_dict(conn, row)


def _update_task(task_id: int, name: str | None, description: str | None) -> dict | None:
    """Update a task's name and/or description. ``None`` means "leave as is"."""
    with _db_conn() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        new_name = row["name"] if name is None else name.strip() or row["name"]
        new_desc = row["description"] if description is None else description.strip()
        conn.execute(
            "UPDATE tasks SET name = ?, description = ?, updated_at = ? WHERE id = ?",
            (new_name, new_desc, time.time(), task_id),
        )
        row = conn.execute(
            """
            SELECT t.*, p.name AS project_name FROM tasks t
            LEFT JOIN projects p ON p.id = t.project_id WHERE t.id = ?
            """,
            (task_id,),
        ).fetchone()
        return _task_dict(row)


def _task_dict(row) -> dict:
    return {
        "id": row["id"],
        "project_id": row["project_id"],
        "project_name": row["project_name"] if "project_name" in row.keys() else None,
        "name": row["name"],
        "description": row["description"] if "description" in row.keys() else "",
        "status": row["status"],
        "target_name": row["target_name"],
        "target_path": row["target_path"],
        "target_sha256": row["target_sha256"],
        "target_size": row["target_size"],
        "mode": row["mode"],
        "capabilities": _json_list(row["capabilities"]),
        "modules": row["modules"],
        "command": _json_list(row["command"]),
        "exit_code": row["exit_code"],
        "duration_ms": row["duration_ms"],
        "analyzer_count": row["analyzer_count"],
        "finding_count": row["finding_count"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _without_report(data: dict) -> dict:
    """Return a copy of an analysis envelope without the ephemeral report link."""
    copied = dict(data)
    copied["report"] = None
    return copied


def _create_task(
    project_id: int,
    task_name: str,
    data: dict,
    target_name: str = "",
    target_path: str = "",
    mode: str = "multi",
    capabilities: tuple[str, ...] = (),
    modules: str = "",
    description: str = "",
) -> dict | None:
    """Persist an analysis envelope (the /api/analyze response) as a task."""
    if _get_project(project_id) is None:
        return None
    payload = data.get("payload") if isinstance(data, dict) else None
    result = (payload or {}).get("result") if isinstance(payload, dict) else None
    target = result.get("target") if isinstance(result, dict) and isinstance(result.get("target"), dict) else {}
    results = result.get("results") if isinstance(result, dict) and isinstance(result.get("results"), dict) else {}
    findings = result.get("findings") if isinstance(result, dict) else []
    if not isinstance(findings, list):
        findings = []
    name = task_name.strip() or f"{target_name or '任务'}·{time.strftime('%Y-%m-%d %H:%M:%S')}"
    now = time.time()
    joined_caps = ",".join(capabilities)
    with _db_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO tasks (
                project_id, name, description, status, target_name, target_path, target_sha256, target_size,
                mode, capabilities, modules, command, exit_code, duration_ms,
                analyzer_count, finding_count, result_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                name,
                description,
                "success" if data.get("ok") else "error",
                target_name or target.get("name") or "",
                target_path or target.get("path") or "",
                target.get("sha256"),
                target.get("size"),
                mode,
                joined_caps,
                modules,
                json.dumps(data.get("command") or [], ensure_ascii=False),
                data.get("exit_code"),
                data.get("duration_ms"),
                len(results),
                len(findings),
                json.dumps(_without_report(data), ensure_ascii=False),
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT t.*, p.name AS project_name FROM tasks t
            LEFT JOIN projects p ON p.id = t.project_id WHERE t.id = ?
            """, (cursor.lastrowid,)
        ).fetchone()
        return _task_dict(row)


def _list_tasks(project_id: int | None = None) -> list[dict]:
    sql = """
        SELECT t.*, p.name AS project_name FROM tasks t
        LEFT JOIN projects p ON p.id = t.project_id
    """
    params: tuple = ()
    if project_id is not None:
        sql += " WHERE t.project_id = ?"
        params = (project_id,)
    sql += " ORDER BY t.created_at DESC, t.id DESC"
    with _db_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_task_dict(row) for row in rows]


def _get_task(task_id: int) -> dict | None:
    with _db_conn() as conn:
        row = conn.execute(
            """
            SELECT t.*, p.name AS project_name FROM tasks t
            LEFT JOIN projects p ON p.id = t.project_id WHERE t.id = ?
            """, (task_id,)
        ).fetchone()
        if row is None:
            return None
        task = _task_dict(row)
        try:
            task["result"] = json.loads(row["result_json"] or "null")
        except (TypeError, ValueError):
            task["result"] = None
        return task


def _delete_task(task_id: int) -> bool:
    with _db_conn() as conn:
        cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        return cursor.rowcount > 0


def _parse_id(value: str | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

# The single in-flight /api/analyze child process. /api/cancel flips
# ``cancelled`` and kills the process so the waiting request can return early
# instead of burning the rest of the timeout.
_RUN_LOCK = threading.Lock()
_RUN_STATE: dict[str, object] = {"proc": None, "cancelled": False}

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

# Whether the console is reachable beyond this machine. Loopback-only (the
# default) keeps every feature open: the only client is the local user. When
# the server binds a non-loopback interface (cloud deploy via ``PORT``), the
# ``path`` parameter becomes an unauthenticated read primitive -- any absolute
# path on the host could be analyzed and its facts returned to a stranger --
# so remote callers are restricted to the project's own samples/reports tree.
_REMOTE_BIND = False


def _path_allowed(candidate: Path) -> bool:
    """Whether ``candidate`` may be analyzed, given how the server is bound.

    On loopback the local user already has full file access, so nothing is
    restricted. On a remote bind the target must live under the project root
    (the samples in ``in/`` or a user-provided directory inside it); the temp
    upload path is exempt because the caller supplied those bytes, not a host
    path.
    """
    if not _REMOTE_BIND:
        return True
    try:
        resolved = candidate.resolve()
    except OSError:
        return False
    # Uploaded bytes go to a system temp path, but those never travel through
    # the ``path`` parameter, so only host-supplied paths reach this check.
    roots = (REPO_ROOT.resolve(), SAMPLES_DIR.resolve())
    return any(resolved == root or root in resolved.parents for root in roots)


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


# -- 预置分析脚本 ---------------------------------------------------------


def _preset_id(name: str) -> str:
    """Derive a stable, filesystem- and URL-safe id from a preset display name.

    中文名无法直接作为文件名（URL 里也要转义），所以只保留 ASCII 字符；
    当名字里没有可用 ASCII 时回退到内容哈希，保证同一个名字映射到同一个 id。
    """
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("._-")
    if not slug:
        digest = hashlib.sha1(name.strip().encode("utf-8")).hexdigest()[:12]
        return f"preset-{digest}"
    return slug[:60]


def _preset_path(preset_id: str) -> Path | None:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", preset_id or ""):
        return None
    return Path(PRESETS_DIR) / f"{preset_id}.json"


def _list_presets() -> list[dict]:
    directory = Path(PRESETS_DIR)
    if not directory.is_dir():
        return []
    presets = []
    for path in directory.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        presets.append(
            {
                "id": path.stem,
                "name": str(data.get("name") or path.stem),
                "mode": "scan" if data.get("mode") == "scan" else "multi",
                "capabilities": [
                    str(item) for item in data.get("capabilities") or [] if item
                ],
                "updated_at": path.stat().st_mtime,
            }
        )
    presets.sort(key=lambda item: item["name"].lower())
    return presets


def _save_preset(name: str, mode: str, capabilities: list[str]) -> dict:
    """Write one preset file. Raises ValueError with a user-facing message."""
    display = name.strip()
    if not display:
        raise ValueError("预置名称不能为空")
    if not _PRESET_NAME_RE.match(display):
        raise ValueError("预置名称只能包含中英文、数字、空格和 . _ -，最长 60 字")
    mode = "scan" if mode == "scan" else "multi"
    caps = sorted({item for item in capabilities if item})
    if mode == "multi":
        if not caps:
            raise ValueError("至少勾选一项分析能力后才能保存")
        # Load the catalog first so an unknown id is caught on the very first
        # save too; only when the catalog itself is unavailable (broken
        # environment) do we skip the check, matching /api/health's tolerance.
        _load_catalog()
        known = _known_capability_ids()
        unknown = [item for item in caps if known and item not in known]
        if unknown:
            raise ValueError("未知分析能力: " + ", ".join(unknown))
    else:
        caps = []
    directory = Path(PRESETS_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    preset_id = _preset_id(display)
    target = _preset_path(preset_id)
    if target is None:  # pragma: no cover - _preset_id already sanitises
        raise ValueError("预置名称不合法")
    existing = len([path for path in directory.glob("*.json")])
    if not target.exists() and existing >= MAX_PRESETS_KEPT:
        raise ValueError(f"预置数量已达上限 {MAX_PRESETS_KEPT}，请先删除不用的预置")
    payload = {"name": display, "mode": mode, "capabilities": caps}
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "id": preset_id,
        "name": display,
        "mode": mode,
        "capabilities": caps,
        "updated_at": target.stat().st_mtime,
    }


def _delete_preset(preset_id: str) -> bool:
    path = _preset_path(preset_id)
    if path is None or not path.is_file():
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True


def _kill(process: subprocess.Popen) -> None:
    """Terminate a child process, tolerating one that already exited.

    Deliberately does *not* call ``communicate()``: the analysis thread owns
    the pipes, and two threads reaping the same process would race. Killing is
    enough — the waiting ``communicate(timeout=...)`` returns right after.
    """
    try:
        process.kill()
    except OSError:
        pass


def request_cancel() -> bool:
    """Ask the in-flight analysis to stop. Returns True if something was running."""
    with _RUN_LOCK:
        process = _RUN_STATE["proc"]
        if process is None:
            return False
        _RUN_STATE["cancelled"] = True
    _kill(process)  # type: ignore[arg-type]
    return True


def _save_report(payload: object, target_name: str) -> dict:
    """Persist one analysis payload to ``reports/`` and describe it.

    Returns ``{"path", "name", "size", "url"}`` on success, or
    ``{"error": ...}`` when the write fails. A failed write must never fail
    the analysis itself: the caller still returns the payload.
    """
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"无法创建 reports 目录: {exc}"}

    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(target_name).stem or "target")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    # 同秒内多次运行靠序号区分。检查与写入必须是原子的：并发请求若都用
    # exists() 判断再 write，会同时判定"不存在"而互相覆盖，所以这里用
    # O_CREAT|O_EXCL 原子创建——文件已存在时 open 直接失败，再递增序号重试。
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    data = text.encode("utf-8")
    name = None
    path = None
    for serial in range(MAX_REPORT_SERIAL_TRIES):
        suffix = f"-{serial}" if serial else ""
        name = f"{stem}-{stamp}{suffix}.json"
        path = REPORTS_DIR / name
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        except OSError as exc:
            return {"error": f"写入报告失败: {exc}"}
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        except OSError as exc:
            return {"error": f"写入报告失败: {exc}"}
        break
    else:
        return {"error": f"写入报告失败: 无法为 {stem}-{stamp} 生成唯一文件名"}


    _prune_reports()
    return {
        "path": str(path),
        "name": name,
        "size": path.stat().st_size,
        "url": f"/api/report?name={name}",
    }


def _prune_reports() -> None:
    """Keep only the newest MAX_REPORTS_KEPT reports."""
    with _REPORTS_LOCK:
        try:
            files = sorted(
                (p for p in REPORTS_DIR.glob("*.json") if p.is_file()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return
        for stale in files[MAX_REPORTS_KEPT:]:
            try:
                stale.unlink()
            except OSError:
                pass


def _report_path(name: str) -> Path | None:
    """Resolve a report filename inside REPORTS_DIR, or None if unsafe."""
    # 只接受纯文件名：任何路径分隔符或父目录引用都拒绝，防止越权读取
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.json", name or ""):
        return None
    candidate = (REPORTS_DIR / name).resolve()
    try:
        candidate.relative_to(REPORTS_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _directory_has_files(
    root: Path,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
) -> bool:
    """Whether the directory holds a file that survives the filters.

    The expansion itself is the CLI's job; this only answers the question
    early, so an empty selection gets a clear message instead of a
    confusing subprocess error.
    """
    from soinsight.application.target_resolver import TargetResolver

    try:
        targets = TargetResolver().resolve_many(
            [root], include=include, exclude=exclude
        )
    except Exception:
        return False
    return bool(targets)


def _run_analysis(
    mode: str,
    capability: str,
    modules: str,
    target: Path,
    capabilities: tuple[str, ...] = (),
    extra_targets: tuple[Path, ...] = (),
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
) -> dict:
    """Run one analysis in a subprocess and return the parsed JSON payload.

    ``extra_targets`` turns the run into a batch: the CLI receives several
    targets and scans each of them, so a directory can be analyzed in one
    request.
    """
    argv = [sys.executable, "-m", "soinsight"]
    targets = [str(target), *(str(item) for item in extra_targets)]
    if mode == "scan":
        argv += ["scan", *targets, "--module-available", modules]
    elif mode == "multi":
        argv += ["scan", *targets, "--enable", ",".join(capabilities)]
    else:
        # A single capability command takes exactly one target, so a batch
        # is only meaningful for the composed scans.
        argv += capability.split(".") + [str(target)]
    for pattern in include:
        argv += ["--include", pattern]
    for pattern in exclude:
        argv += ["--exclude", pattern]
    argv += ["--format", "json", "--no-cache", "--quiet"]

    env = _transform_env()

    started = time.perf_counter()
    with _RUN_LOCK:
        _RUN_STATE["cancelled"] = False
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=str(REPO_ROOT),
        )
    except OSError as exc:  # pragma: no cover - 环境相关
        return {
            "ok": False,
            "error": f"无法启动分析子进程: {exc}",
            "command": argv,
            "exit_code": None,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "payload": None,
            "stderr_tail": "",
        }

    with _RUN_LOCK:
        _RUN_STATE["proc"] = process
    try:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                if time.perf_counter() - started <= ANALYSIS_TIMEOUT:
                    continue
                _kill(process)
                process.communicate()      # 只在本线程收尾，避免与取消请求抢管道
                return {
                    "ok": False,
                    "error": f"分析超时（超过 {ANALYSIS_TIMEOUT} 秒）",
                    "command": argv,
                    "exit_code": None,
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "payload": None,
                    "stderr_tail": "",
                }
    finally:
        with _RUN_LOCK:
            _RUN_STATE["proc"] = None
            cancelled = bool(_RUN_STATE["cancelled"])
            _RUN_STATE["cancelled"] = False

    duration_ms = int((time.perf_counter() - started) * 1000)
    stdout = stdout or ""
    payload = None
    parse_error = None
    try:
        payload = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError as exc:
        parse_error = f"CLI 输出不是有效 JSON: {exc}"
    # 取消后如果子进程其实已经把完整结果写完，就照常返回结果，别丢掉已完成的分析
    if cancelled and payload is None:
        return {
            "ok": False,
            "error": "分析已取消",
            "command": argv,
            "exit_code": process.returncode,
            "duration_ms": duration_ms,
            "payload": None,
            "stderr_tail": "",
        }
    if payload is None and parse_error is None:
        stderr_text = stderr or ""
        if "ModuleNotFoundError" in stderr_text:
            parse_error = (
                "分析子进程缺少依赖（子进程使用 "
                f"{sys.executable}）。请用安装了项目依赖的 Python 运行本服务，"
                "例如项目虚拟环境：.venv\\Scripts\\python web\\server.py"
            )
        else:
            parse_error = f"CLI 未产生 JSON 输出（退出码 {process.returncode}）"
    # 结果落盘，页面只拿路径；写入失败不影响分析本身
    report = _save_report(stdout if payload is not None else None, target.name)
    return {
        # A non-zero exit code with a valid payload is still a real analysis
        # result (e.g. an analyzer reporting FAILED); the page renders it.
        "ok": payload is not None,
        "error": parse_error,
        "command": argv,
        "exit_code": process.returncode,
        "duration_ms": duration_ms,
        "payload": payload,
        "report": report,
        "stdout_tail": stdout[-4000:] if parse_error else "",
        "stderr_tail": (stderr or "")[-2000:],
    }


def _now_stamp() -> str:
    return time.strftime("%H:%M:%S")


def _job_log(job: dict, text: str) -> None:
    with _JOBS_LOCK:
        job["lines"].append({"t": _now_stamp(), "text": text})


def _prune_jobs() -> None:
    """Keep at most MAX_JOBS_KEPT jobs, evicting only finished ones.

    A job that is still running must never be evicted: its worker thread
    holds ``_ANALYSIS_LOCK`` and owns the upload temp file, so dropping its
    record would leave an orphaned thread and a temp file nobody unlinks.
    When every job is still running the dict is allowed to exceed the cap
    temporarily; they get pruned as they finish.
    """
    with _JOBS_LOCK:
        overflow = len(_JOBS) - MAX_JOBS_KEPT
        if overflow <= 0:
            return
        finished = sorted(
            (key for key in _JOBS if _JOBS[key].get("done")),
            key=lambda key: _JOBS[key]["started"],
        )
        for key in finished[:overflow]:
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


def _start_job(
    target: Path,
    display_name: str,
    cleanup: bool = False,
    project_id: int | None = None,
    task_name: str = "",
) -> dict:
    """Create a background full scan job and return its tracking record."""
    job_id = uuid.uuid4().hex[:12]
    argv = [sys.executable, "-m", "soinsight", "scan", str(target)]
    argv += ["--format", "json", "--no-cache"]
    job = {
        "id": job_id,
        "filename": display_name,
        "target": str(target),
        "cleanup_target": cleanup,
        "project_id": project_id,
        "task_name": task_name,
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


def _persist_job_task(job: dict) -> None:
    """Persist a finished background job as a task when it belongs to a project."""
    if not job.get("project_id"):
        return
    payload = job.get("payload")
    envelope = {
        "ok": job.get("error") is None and payload is not None,
        "error": job.get("error"),
        "command": job.get("command"),
        "exit_code": job.get("exit_code"),
        "duration_ms": job.get("duration_ms"),
        "payload": payload,
        "report": None,
    }
    task = _create_task(
        job["project_id"],
        job.get("task_name") or "",
        envelope,
        target_name=job.get("filename") or job.get("target") or "",
        target_path=job.get("target") or "",
        mode="scan",
        capabilities=(),
        modules="basic,advanced,security",
    )
    if task:
        job["task"] = task


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
        _persist_job_task(job)
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

# 只有文本类资源值得压缩；图片（png/ico）本身已是压缩格式。
_GZIP_SUFFIXES = frozenset({".html", ".css", ".js", ".json", ".svg", ".md"})
# 小于这个体积压缩收益不抵开销，直接原样发送。
_GZIP_MIN_BYTES = 1024

_JOB_LOG_ROUTE = re.compile(r"/api/jobs/([0-9a-f]{12})/log")
_JOB_RESULT_ROUTE = re.compile(r"/api/jobs/([0-9a-f]{12})/result")
_PROJECT_TASKS_ROUTE = re.compile(r"/api/projects/(\d+)/tasks")
_PROJECT_ITEM_ROUTE = re.compile(r"/api/projects/(\d+)")
_TASK_ROUTE = re.compile(r"/api/tasks/(\d+)")
_PRESET_ROUTE = re.compile(r"/api/presets/([A-Za-z0-9._-]{1,80})")


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
            "task": job.get("task"),
        }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"SOInsightWeb/{__version__}"

    def log_message(self, fmt, *args):  # noqa: N802 - stdlib name
        # A timestamp per line: ThreadingHTTPServer interleaves concurrent
        # requests on stderr, and without a clock the lines cannot be ordered
        # against a job's own timestamps.
        stamp = time.strftime("%H:%M:%S")
        sys.stderr.write("  %s %s - %s\n" % (stamp, self.address_string(), fmt % args))

    # -- helpers ---------------------------------------------------------
    def _send_json(self, obj: object, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self, length: int) -> bytes:
        """Read exactly ``length`` body bytes, or fewer if the client stalls.

        A single ``rfile.read(length)`` blocks until the declared number of
        bytes arrive or the connection closes, so a client that advertises a
        large ``Content-Length`` and then trickles nothing can pin one of the
        server's threads indefinitely. Reading in chunks against a wall-clock
        deadline returns early instead, and the partial read is treated as a
        malformed request by the caller (the upload branch rejects an empty or
        short body through its own checks).
        """
        if length <= 0:
            return b""
        deadline = time.monotonic() + _BODY_READ_TIMEOUT
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            if time.monotonic() >= deadline:
                break
            chunk = self.rfile.read(min(remaining, _BODY_READ_CHUNK))
            if not chunk:
                break  # peer closed early
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _discard_body(self) -> None:
        """Drain an unused request body so keep-alive connections stay in sync."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if 0 < length <= MAX_UPLOAD_BYTES:
            self.rfile.read(length)

    def _serve_static(self, route: str) -> None:
        relative = route.lstrip("/") or "index.html"
        target = (SITE_DIR / relative).resolve()
        if SITE_DIR != target and SITE_DIR not in target.parents:
            self._send_json({"ok": False, "error": "禁止访问"}, HTTPStatus.FORBIDDEN)
            return
        # Only known web assets may be served. This directory also contains
        # server.py and start-web.bat; without this allowlist they (and any
        # __pycache__ artifact) would be downloadable as source code.
        content_type = CONTENT_TYPES.get(target.suffix.lower())
        if content_type is None or not target.is_file():
            self._send_json(
                {"ok": False, "error": f"文件不存在: {route}"}, HTTPStatus.NOT_FOUND
            )
            return
        body = target.read_bytes()
        stat = target.stat()
        # 用「大小-修改时间」生成弱 ETag：控制台资源是开发中的静态文件，每次改动都会变。
        etag = f'W/"{stat.st_size:x}-{int(stat.st_mtime):x}"'
        # 页面资源没有缓存头时浏览器按启发式规则缓存，改了代码刷新后仍跑旧逻辑，
        # 表现为"页面行为和代码对不上"。no-cache + must-revalidate 让每次刷新
        # 都回源校验，同时允许 304 省流量。
        cache_control = "no-cache, must-revalidate"

        # 命中缓存：回 304，连响应体都不用发。
        if etag in (self.headers.get("If-None-Match") or ""):
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", cache_control)
            self.end_headers()
            return

        # 文本资源按客户端支持的编码压缩后再发，控制台体积较大，收益明显。
        encoded = body
        gzip_ok = (
            target.suffix.lower() in _GZIP_SUFFIXES
            and len(body) >= _GZIP_MIN_BYTES
            and "gzip" in (self.headers.get("Accept-Encoding") or "").lower()
        )
        if gzip_ok:
            encoded = gzip.compress(body, 6)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", cache_control)
        if gzip_ok:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.end_headers()
        self.wfile.write(encoded)

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
        elif route == "/api/presets":
            self._send_json({"ok": True, "presets": _list_presets()})
        elif route == "/api/projects":
            self._send_json({"ok": True, "projects": _list_projects()})
        elif route == "/api/tasks":
            self._send_json({"ok": True, "tasks": _list_tasks()})
        elif _PROJECT_TASKS_ROUTE.fullmatch(route):
            project_id = int(_PROJECT_TASKS_ROUTE.fullmatch(route).group(1))
            self._send_json(
                {"ok": True, "project_id": project_id, "tasks": _list_tasks(project_id)}
            )
        elif _TASK_ROUTE.fullmatch(route):
            task = _get_task(int(_TASK_ROUTE.fullmatch(route).group(1)))
            if task is None:
                self._send_json(
                    {"ok": False, "error": "任务不存在"}, HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"ok": True, "task": task})
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
        elif route == "/api/report":
            self._serve_report(parsed.query)
        else:
            self._serve_static(route)

    def _serve_report(self, query: str) -> None:
        """Download a saved analysis report by filename."""
        params = {key: values[0] for key, values in parse_qs(query).items()}
        path = _report_path(params.get("name", ""))
        if path is None:
            self._send_json(
                {"ok": False, "error": "报告不存在或文件名不合法"},
                HTTPStatus.NOT_FOUND,
            )
            return
        try:
            body = path.read_bytes()
        except OSError as exc:
            self._send_json(
                {"ok": False, "error": f"读取报告失败: {exc}"},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{path.name}"'
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        parsed = urlparse(self.path)
        if parsed.path == "/api/cancel":
            self._discard_body()
            self._send_json({"ok": True, "cancelled": request_cancel()})
            return

        params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        if parsed.path == "/api/projects":
            self._discard_body()
            name = params.get("name", "").strip()
            if not name:
                self._send_json(
                    {"ok": False, "error": "项目名称不能为空"},
                    HTTPStatus.BAD_REQUEST,
                )
                return
            project = _create_project(name, params.get("description", "").strip())
            self._send_json({"ok": True, "project": project})
            return

        if parsed.path == "/api/presets":
            self._discard_body()
            capabilities = [
                item.strip()
                for item in params.get("capabilities", "").split(",")
                if item.strip()
            ]
            try:
                preset = _save_preset(
                    params.get("name", ""), params.get("mode", "multi"), capabilities
                )
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            except OSError as exc:
                self._send_json(
                    {"ok": False, "error": f"保存预置失败: {exc}"},
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return
            self._send_json({"ok": True, "preset": preset})
            return

        if parsed.path not in ("/api/analyze", "/api/jobs"):
            self._send_json(
                {"ok": False, "error": f"未知路径: {parsed.path}"},
                HTTPStatus.NOT_FOUND,
            )
            return

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
        project_id = _parse_id(params.get("project_id"))
        task_name = params.get("task_name", "").strip()
        if project_id is not None and _get_project(project_id) is None:
            self._send_json(
                {"ok": False, "error": "项目不存在或已被删除"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        path_param = params.get("path", "").strip()
        include = tuple(
            item.strip()
            for item in params.get("include", "").split(",")
            if item.strip()
        )
        exclude = tuple(
            item.strip()
            for item in params.get("exclude", "").split(",")
            if item.strip()
        )

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(
                {"ok": False, "error": "Content-Length 不是合法整数"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        if length < 0:
            self._send_json(
                {"ok": False, "error": "Content-Length 不能为负数"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        if length > MAX_UPLOAD_BYTES:
            self._send_json(
                {"ok": False, "error": f"文件超过 {MAX_UPLOAD_BYTES // 1048576} MiB 上限"},
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return
        body = self._read_body(length)

        temp_path: str | None = None
        display_name = ""
        try:
            target: Path
            extra_targets: tuple[Path, ...] = ()
            if path_param:
                candidate = Path(path_param)
                if not candidate.is_absolute() or not candidate.exists():
                    self._send_json(
                        {"ok": False, "error": f"服务器路径无效: {path_param}"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                if not _path_allowed(candidate):
                    # Remote bind: an arbitrary host path would be an
                    # unauthenticated local-file read, so confine targets to
                    # the project tree. Loopback keeps full access.
                    self._send_json(
                        {
                            "ok": False,
                            "error": "远程访问只允许分析项目目录内的文件，"
                            "请改用文件上传，或在服务器本机访问",
                        },
                        HTTPStatus.FORBIDDEN,
                    )
                    return
                display_name = candidate.name
                if candidate.is_dir():
                    # The directory is handed to the CLI, which expands it
                    # with the same rules as a command line run. Doing it
                    # there keeps one implementation of the expansion and
                    # gives the answer the same shape.
                    if not _directory_has_files(candidate, include, exclude):
                        self._send_json(
                            {
                                "ok": False,
                                "error": f"目录中没有可分析的文件: {path_param}",
                            },
                            HTTPStatus.BAD_REQUEST,
                        )
                        return
                    target = candidate
                else:
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
                display_name = filename

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
                record = _start_job(
                    target,
                    display_name or target.name,
                    cleanup=not path_param,
                    project_id=project_id,
                    task_name=task_name,
                )
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
                result = _run_analysis(
                    mode,
                    capability,
                    modules,
                    target,
                    capabilities,
                    extra_targets=extra_targets,
                    include=include,
                    exclude=exclude,
                )
            finally:
                _ANALYSIS_LOCK.release()
            if project_id is not None:
                task = _create_task(
                    project_id,
                    task_name,
                    result,
                    target_name=display_name or target.name,
                    target_path=str(target),
                    mode=mode,
                    capabilities=capabilities,
                    modules="" if mode != "scan" else modules,
                    description=params.get("task_description", "").strip(),
                )
                if task:
                    result = dict(result)
                    result["task"] = task
            self._send_json(result)
        finally:
            # Job uploads are owned by the background worker: it unlinks the
            # temp target after the child process has finished with it.
            if temp_path and not is_job:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib name
        parsed = urlparse(self.path)
        project_match = _PROJECT_ITEM_ROUTE.fullmatch(parsed.path)
        task_match = _TASK_ROUTE.fullmatch(parsed.path)
        if project_match:
            self._discard_body()
            deleted = _delete_project(int(project_match.group(1)))
            if not deleted:
                self._send_json(
                    {"ok": False, "error": "项目不存在"}, HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"ok": True, "deleted": "project"})
            return
        if task_match:
            self._discard_body()
            deleted = _delete_task(int(task_match.group(1)))
            if not deleted:
                self._send_json(
                    {"ok": False, "error": "任务不存在"}, HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"ok": True, "deleted": "task"})
            return
        preset_match = _PRESET_ROUTE.fullmatch(parsed.path)
        if preset_match:
            self._discard_body()
            if not _delete_preset(preset_match.group(1)):
                self._send_json(
                    {"ok": False, "error": "预置不存在"}, HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"ok": True, "deleted": "preset"})
            return
        self._send_json(
            {"ok": False, "error": f"未知路径: {parsed.path}"},
            HTTPStatus.NOT_FOUND,
        )

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib name
        """Rename a project or task and/or edit its description."""
        parsed = urlparse(self.path)
        params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        project_match = _PROJECT_ITEM_ROUTE.fullmatch(parsed.path)
        task_match = _TASK_ROUTE.fullmatch(parsed.path)
        if not project_match and not task_match:
            self._discard_body()
            self._send_json(
                {"ok": False, "error": f"未知路径: {parsed.path}"},
                HTTPStatus.NOT_FOUND,
            )
            return
        # PATCH 只读 query string；先排空可能存在的请求体，保持 keep-alive 同步。
        self._discard_body()
        # name / description 缺省表示"保持原样"，空字符串表示"清空描述"
        name = params["name"] if "name" in params else None
        description = params["description"] if "description" in params else None
        if project_match:
            updated = _update_project(int(project_match.group(1)), name, description)
            if updated is None:
                self._send_json(
                    {"ok": False, "error": "项目不存在"}, HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"ok": True, "project": updated})
            return
        updated = _update_task(int(task_match.group(1)), name, description)
        if updated is None:
            self._send_json(
                {"ok": False, "error": "任务不存在"}, HTTPStatus.NOT_FOUND
            )
            return
        self._send_json({"ok": True, "task": updated})

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


def run_console(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    *,
    timeout: int = 180,
    open_browser: bool = True,
) -> int:
    """Start the console and serve until it is interrupted.

    The command line (``soinsight web``) and the script (``web/server.py``)
    both come through here, so there is one server and one set of rules.
    """
    global ANALYSIS_TIMEOUT, _REMOTE_BIND

    ANALYSIS_TIMEOUT = max(10, timeout)

    # Cloud deploy injects PORT and expects a public bind on 0.0.0.0; locally we
    # keep the loopback-only default so the server never exposes the host.
    env_port = os.environ.get("PORT")
    if env_port:
        port = int(env_port)
        if host == "127.0.0.1":
            host = "0.0.0.0"
    # Anything other than a loopback bind is reachable off-machine, which
    # switches the path allowlist on (see _path_allowed).
    _REMOTE_BIND = host not in ("127.0.0.1", "localhost", "::1")

    _load_catalog()
    if _STATE["error"]:
        print(f"警告: 产品目录加载失败（{_STATE['error']}）")
        print("请确认当前 Python 能 import soinsight（需要 PyYAML，且 src/ 存在）。")

    server = None
    for candidate in range(port, port + 20):
        try:
            server = ThreadingHTTPServer((host, candidate), Handler)
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

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SOInsight Web 控制台本地服务器（默认只绑定 127.0.0.1）"
    )
    parser.add_argument("--host", default="127.0.0.1", help="绑定地址（默认 127.0.0.1；检测到 PORT 环境变量时自动改为 0.0.0.0）")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="起始端口（默认 8765；被 PORT 环境变量覆盖）")
    parser.add_argument("--timeout", type=int, default=180, help="单次分析超时秒数（默认 180）")
    parser.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args(argv)

    return run_console(
        args.host,
        args.port,
        timeout=args.timeout,
        open_browser=not args.no_open,
    )


if __name__ == "__main__":
    raise SystemExit(main())
