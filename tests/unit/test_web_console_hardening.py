"""Guards for three console hardening fixes.

Each test pins a defect that a review of ``soinsight.web.console`` exposed
and that a passing build had hidden, because the console's own tests only
exercise the happy loopback path:

* concurrent reports written in the same second could overwrite each other
  (the ``exists()`` check and the ``write`` were not atomic);
* ``_prune_jobs`` could evict a still-running job, orphaning its worker
  thread and its upload temp file;
* on a non-loopback bind the ``path`` parameter was an unauthenticated
  local-file read, because any absolute host path was analyzed and its
  facts returned to the caller.
"""

import threading
import time

import pytest

from soinsight.web import console


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    target = tmp_path / "reports"
    monkeypatch.setattr(console, "REPORTS_DIR", target)
    return target


def test_concurrent_reports_in_one_second_do_not_collide(reports_dir):
    """Two same-second saves must produce two files, not overwrite one."""
    names: list[str] = []
    errors: list[str] = []

    def _save():
        result = console._save_report({"ok": 1}, "libsame.so")
        if "error" in result:
            errors.append(result["error"])
        else:
            names.append(result["name"])

    threads = [threading.Thread(target=_save) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == [], errors
    assert len(names) == 8
    assert len(set(names)) == 8, "a later save overwrote an earlier one"
    files = list(reports_dir.glob("libsame-*.json"))
    assert len(files) == 8


def test_prune_jobs_never_evicts_a_running_job(monkeypatch):
    console._JOBS.clear()
    monkeypatch.setattr(console, "MAX_JOBS_KEPT", 1)
    try:
        # The oldest job is still running; several finished jobs are newer.
        # Under the old "evict the oldest" rule the running job would be the
        # first dropped, orphaning its worker; now only finished jobs go.
        running = {"id": "a" * 12, "started": 1.0, "done": False}
        console._JOBS[running["id"]] = running
        for index in range(3):
            console._JOBS[f"{index:012x}"] = {
                "id": f"{index:012x}",
                "started": 2.0 + index,
                "done": True,
            }

        console._prune_jobs()

        assert running["id"] in console._JOBS, "the running job was evicted"
        # Overflow was four against a cap of one; only the finished jobs go.
        assert len(console._JOBS) == 1
    finally:
        console._JOBS.clear()


def test_remote_bind_confines_path_to_the_project_tree(tmp_path, monkeypatch):
    outside = tmp_path / "elsewhere.so"
    outside.write_bytes(b"\x7fELF")
    monkeypatch.setattr(console, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.setattr(console, "SAMPLES_DIR", tmp_path / "repo" / "in")
    (tmp_path / "repo" / "in").mkdir(parents=True)
    inside = tmp_path / "repo" / "in" / "sample.so"
    inside.write_bytes(b"\x7fELF")

    monkeypatch.setattr(console, "_REMOTE_BIND", True)
    assert console._path_allowed(inside) is True
    assert console._path_allowed(outside) is False

    # Loopback keeps full access: the local user already has it.
    monkeypatch.setattr(console, "_REMOTE_BIND", False)
    assert console._path_allowed(outside) is True


def test_read_body_returns_early_when_the_peer_sends_less_than_it_declared():
    """A stalled upload must not pin the thread until the full length arrives.

    The old ``rfile.read(length)`` blocked until the declared byte count
    arrived or the socket closed, so a client that advertised a large body
    and trickled nothing could hold a worker indefinitely.
    """
    handler = console.Handler.__new__(console.Handler)

    # Sends one chunk, then blocks forever -- the stalled-upload shape.
    class _StallingBody:
        def __init__(self):
            self._sent = False

        def read(self, _size):
            if not self._sent:
                self._sent = True
                return b"\x7fELF"
            time.sleep(2)  # outlasts the deadline; short enough for the suite
            return b""

    handler.rfile = _StallingBody()

    # A short deadline keeps the test fast; the stalled read outlasts it.
    monkey = pytest.MonkeyPatch()
    monkey.setattr(console, "_BODY_READ_TIMEOUT", 0.2)
    try:
        body = handler._read_body(1 << 20)
    finally:
        monkey.undo()

    # Whatever arrived before the deadline is returned; the thread is freed.
    assert body == b"\x7fELF"


def test_read_body_reads_exactly_the_declared_length():
    handler = console.Handler.__new__(console.Handler)

    class _FullBody:
        def __init__(self, payload):
            self._payload = payload

        def read(self, size):
            chunk = self._payload[:size]
            self._payload = self._payload[size:]
            return chunk

    payload = b"x" * 5000
    handler.rfile = _FullBody(payload)

    assert handler._read_body(len(payload)) == payload
