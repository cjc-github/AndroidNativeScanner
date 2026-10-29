"""Dynamic-execution substrate: authorization gate, sandbox detection, executor.

Running untrusted code is a different kind of capability from static analysis, so
this module makes the two preconditions explicit and hard to skip:

* **Authorization** is opt-in and default-deny. Nothing runs unless the config
  says so (`dynamic_execution.authorized`) *and*, when an allow-list is present,
  the target is on it. A refusal is a normal outcome with a diagnostic, not a
  crash.
* **Isolation** is a detected primitive, never an assumption. The module knows
  how to wrap a command with ``bwrap``, ``firejail``, ``docker`` or ``unshare``,
  and it has no fallback to a bare subprocess: if no sandbox is installed the
  executor refuses rather than running untrusted code on the host.

``plan()`` and ``run()`` are separate. ``DryRunExecutor`` only produces the
command line it would have executed, which is what the ``dynamic.*`` analyzers
use by default; actually starting a process needs an executor that was built with
``allow_execution=True``, and no built-in analyzer does that yet.
"""

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

__all__ = [
    "Authorization",
    "ExecutionOutcome",
    "ExecutionPlan",
    "ExecutionRefused",
    "ExecutionRequest",
    "Executor",
    "DryRunExecutor",
    "SandboxSpec",
    "SubprocessSandboxExecutor",
    "authorize",
    "build_plan",
    "detect_sandbox",
]

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MEMORY_MIB = 512


class ExecutionRefused(RuntimeError):
    """Execution was refused; the reason is safe to show to the user."""


@dataclass(frozen=True)
class Authorization:
    """Whether this host may execute the target, and why."""

    granted: bool
    reason: str
    allow_listed: bool


@dataclass(frozen=True)
class SandboxSpec:
    """A detected isolation primitive and how to wrap a command with it."""

    name: str
    prefix: tuple[str, ...]

    def wrap(self, command: Sequence[str]) -> tuple[str, ...]:
        return self.prefix + tuple(command)


@dataclass(frozen=True)
class ExecutionRequest:
    """What to run, under which limits."""

    target: Path
    argv: tuple[str, ...]
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    memory_mib: int = DEFAULT_MEMORY_MIB
    allow_network: bool = False
    read_only_root: bool = True
    environment: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionPlan:
    """The fully wrapped command line plus the limits it runs under."""

    argv: tuple[str, ...]
    sandbox: str
    timeout_seconds: int
    memory_mib: int
    allow_network: bool

    def as_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "sandbox": self.sandbox,
            "timeout_seconds": self.timeout_seconds,
            "memory_mib": self.memory_mib,
            "allow_network": self.allow_network,
        }


@dataclass(frozen=True)
class ExecutionOutcome:
    """Result of a real execution."""

    executed: bool
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def _settings(config) -> dict:
    extra = getattr(config, "extra", None) or {}
    settings = extra.get("dynamic_execution")
    return settings if isinstance(settings, dict) else {}


def authorize(config, target: Path) -> Authorization:
    """Decide whether executing ``target`` is authorized by the config."""
    settings = _settings(config)
    if not settings:
        return Authorization(
            granted=False,
            reason=(
                "动态执行默认拒绝：配置中缺少 dynamic_execution 授权块。"
                "若要启用，需显式声明 dynamic_execution.authorized: true。"
            ),
            allow_listed=False,
        )
    if not settings.get("authorized"):
        return Authorization(
            granted=False,
            reason=(
                "动态执行未被授权：dynamic_execution.authorized 不为 true。"
            ),
            allow_listed=False,
        )

    allow_list = settings.get("allow_targets") or ()
    normalized = {os.path.realpath(str(item)) for item in allow_list}
    real_target = os.path.realpath(str(target))
    allow_listed = not normalized or real_target in normalized
    if not allow_listed:
        return Authorization(
            granted=False,
            reason=(
                f"目标 {real_target} 不在 dynamic_execution.allow_targets 白名单内。"
            ),
            allow_listed=False,
        )
    return Authorization(
        granted=True,
        reason="已授权：dynamic_execution.authorized 为 true，且目标在允许范围内。",
        allow_listed=True,
    )


def detect_sandbox() -> SandboxSpec | None:
    """Return the strongest available isolation primitive, if any."""
    if shutil.which("bwrap"):
        # No host filesystem, no network, private /tmp, read-only system dirs.
        return SandboxSpec(
            name="bwrap",
            prefix=(
                "bwrap",
                "--die-with-parent",
                "--unshare-all",
                "--new-session",
                "--proc", "/proc",
                "--dev", "/dev",
                "--tmpfs", "/tmp",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64",
                "--ro-bind", "/bin", "/bin",
                "--ro-bind", "/sbin", "/sbin",
            ),
        )
    if shutil.which("firejail"):
        return SandboxSpec(
            name="firejail",
            prefix=("firejail", "--quiet", "--private", "--net=none"),
        )
    if shutil.which("docker"):
        return SandboxSpec(
            name="docker",
            prefix=(
                "docker", "run", "--rm", "-i", "--network", "none",
                "--read-only", "--cap-drop", "ALL",
            ),
        )
    if shutil.which("unshare"):
        return SandboxSpec(
            name="unshare",
            prefix=("unshare", "--user", "--map-root-user", "--net", "--mount"),
        )
    return None


def build_plan(request: ExecutionRequest, sandbox: SandboxSpec) -> ExecutionPlan:
    """Wrap the request command with the sandbox and the limits."""
    command = list(request.argv)
    if not request.allow_network and sandbox.name == "bwrap":
        command = ["--unshare-net", *command]
    return ExecutionPlan(
        argv=sandbox.wrap(command),
        sandbox=sandbox.name,
        timeout_seconds=request.timeout_seconds,
        memory_mib=request.memory_mib,
        allow_network=request.allow_network,
    )


class Executor(Protocol):
    """Either plans a sandboxed command or runs it."""

    def plan(self, request: ExecutionRequest) -> ExecutionPlan:
        ...

    def run(self, request: ExecutionRequest) -> ExecutionOutcome:
        ...


class DryRunExecutor:
    """Produces the sandboxed command line without starting anything."""

    def __init__(self, sandbox: SandboxSpec) -> None:
        self.sandbox = sandbox

    def plan(self, request: ExecutionRequest) -> ExecutionPlan:
        return build_plan(request, self.sandbox)

    def run(self, request: ExecutionRequest) -> ExecutionOutcome:
        raise ExecutionRefused(
            "DryRunExecutor never starts a process; use SubprocessSandboxExecutor "
            "with allow_execution=True for a real run."
        )


class SubprocessSandboxExecutor:
    """Runs the sandboxed command; requires an explicit opt-in at construction.

    The double opt-in (authorization *and* ``allow_execution``) exists so that a
    future collector cannot silently start executing binaries by constructing an
    executor in passing.
    """

    def __init__(self, sandbox: SandboxSpec, *, allow_execution: bool = False) -> None:
        self.sandbox = sandbox
        self.allow_execution = allow_execution

    def plan(self, request: ExecutionRequest) -> ExecutionPlan:
        return build_plan(request, self.sandbox)

    def run(self, request: ExecutionRequest) -> ExecutionOutcome:
        if not self.allow_execution:
            raise ExecutionRefused(
                "SubprocessSandboxExecutor was built with allow_execution=False."
            )
        import subprocess

        plan = self.plan(request)
        try:
            completed = subprocess.run(
                plan.argv,
                capture_output=True,
                text=True,
                timeout=plan.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionOutcome(
                executed=True,
                returncode=None,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                timed_out=True,
            )
        return ExecutionOutcome(
            executed=True,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
