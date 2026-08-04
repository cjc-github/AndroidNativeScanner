"""Centralized external tool execution boundary."""

from dataclasses import dataclass
from pathlib import Path
import subprocess
from time import perf_counter


@dataclass(frozen=True)
class ToolRequest:
    executable: str
    arguments: tuple[str, ...] = ()
    timeout_seconds: int = 60
    max_output_bytes: int = 10 * 1024 * 1024
    cwd: Path | None = None


@dataclass(frozen=True)
class ToolResult:
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


class ToolRunner:
    def run(self, request: ToolRequest) -> ToolResult:
        started = perf_counter()
        try:
            process = subprocess.run(
                [request.executable, *request.arguments],
                cwd=request.cwd,
                capture_output=True,
                timeout=request.timeout_seconds,
                check=False,
            )
            stdout_bytes = process.stdout
            stderr_bytes = process.stderr
            truncated = (
                len(stdout_bytes) > request.max_output_bytes
                or len(stderr_bytes) > request.max_output_bytes
            )
            stdout = stdout_bytes[: request.max_output_bytes].decode(
                "utf-8", errors="replace"
            )
            stderr = stderr_bytes[: request.max_output_bytes].decode(
                "utf-8", errors="replace"
            )
            return ToolResult(
                return_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=int((perf_counter() - started) * 1000),
                truncated=truncated,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"")[: request.max_output_bytes].decode(
                "utf-8", errors="replace"
            )
            stderr = (exc.stderr or b"")[: request.max_output_bytes].decode(
                "utf-8", errors="replace"
            )
            return ToolResult(
                return_code=-1,
                stdout=stdout,
                stderr=stderr,
                duration_ms=int((perf_counter() - started) * 1000),
                timed_out=True,
            )
