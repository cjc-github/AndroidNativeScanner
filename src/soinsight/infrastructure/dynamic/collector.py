"""Dynamic analysis substrate: the gate, the collector plans and the harness.

Running untrusted code is a different kind of capability from static
analysis, so the preconditions stay explicit and hard to skip:

* **Authorization** is opt-in and default-deny, enforced by
  :func:`soinsight.infrastructure.execution.authorize`.
* **Isolation** is a detected primitive, never an assumption. When no
  sandbox is installed, the collector refuses instead of running untrusted
  code on the host.

What this module adds on top of the execution substrate is the *collector*
side: for each kind of dynamic observation it describes the driver that
would collect the events, the environment the driver needs and the limits it
runs under, and -- for the shared-object case -- the C source of a ``dlopen``
harness that loads the library and calls one entry point.

Nothing here starts a process. The analyzers report the plan; running it
stays a deliberate human step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..execution import (
    DryRunExecutor,
    ExecutionRequest,
    SandboxSpec,
    authorize,
    detect_sandbox,
)

__all__ = [
    "COLLECTOR_KINDS",
    "CollectorSpec",
    "CollectorUnavailable",
    "build_driver_plan",
    "dlopen_harness_source",
    "resolve_dynamic_gate",
    "spec_to_plan",
]

#: The kinds of runtime observation the framework knows how to plan.
COLLECTOR_KINDS = ("trace", "arguments", "memory", "syscalls", "coverage")

#: The isolation primitives a caller may ask for by name.
_SANDBOX_NAMES = ("bwrap", "firejail", "docker", "unshare")


class CollectorUnavailable(RuntimeError):
    """The collector cannot run here; the reason is safe to show."""


@dataclass(frozen=True)
class CollectorSpec:
    """What a collector would need in order to run."""

    kind: str
    """``arguments``, ``memory``, ``syscalls`` or ``coverage``."""
    driver: str
    """The program that performs the observation."""
    entrypoint: str
    """The function the driver calls into the library."""
    environment: dict[str, str] = field(default_factory=dict)
    """Environment variables the driver needs."""
    arguments: tuple[str, ...] = ()
    """Arguments handed to the driver."""
    instrumentation: tuple[str, ...] = ()
    """The observation points the driver watches."""
    limits: dict = field(default_factory=dict)
    """The limits the run stays under."""
    outputs: tuple[str, ...] = ()
    """What the driver produces."""

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "driver": self.driver,
            "entrypoint": self.entrypoint,
            "environment": dict(self.environment),
            "arguments": list(self.arguments),
            "instrumentation": list(self.instrumentation),
            "limits": dict(self.limits),
            "outputs": list(self.outputs),
        }


def resolve_dynamic_gate(
    config,
    target: Path,
    *,
    sandbox: str = "auto",
    timeout_seconds: int = 10,
    memory_mib: int = 512,
) -> dict:
    """Decide whether a collection run may happen, and describe it.

    The returned state is one of:

    ``not-authorized``
        The configuration does not authorize execution.
    ``no-sandbox``
        Execution is authorized but no isolation primitive is available.
    ``planned``
        Everything is in place; ``plan`` holds the sandboxed command line.

    ``plan`` is ``None`` unless the state is ``planned``: no analyzer may
    report a command it would not be allowed to run.
    """
    authorization = authorize(config, target)

    if not authorization.granted:
        return {
            "state": "not-authorized",
            "authorized": False,
            "reason": authorization.reason,
            "sandbox": None,
            "plan": None,
            "diagnostics": [
                {
                    "code": "DYNAMIC_EXECUTION_NOT_AUTHORIZED",
                    "level": "warning",
                    "message": authorization.reason,
                }
            ],
        }

    if sandbox in (None, "", "auto"):
        spec = detect_sandbox()
    elif sandbox == "none":
        spec = None
    elif sandbox in _SANDBOX_NAMES:
        spec = _sandbox_by_name(sandbox)
    else:
        spec = None

    if spec is None:
        reason = (
            "未检测到可用的隔离原语（bwrap / firejail / docker / unshare），"
            "拒绝在宿主上直接执行不可信代码。"
        )
        return {
            "state": "no-sandbox",
            "authorized": True,
            "reason": reason,
            "sandbox": None,
            "plan": None,
            "diagnostics": [
                {
                    "code": "DYNAMIC_SANDBOX_UNAVAILABLE",
                    "level": "warning",
                    "message": reason,
                }
            ],
        }

    request = ExecutionRequest(
        target=target,
        argv=(str(target),),
        timeout_seconds=timeout_seconds,
        memory_mib=memory_mib,
    )
    plan = DryRunExecutor(spec).plan(request)
    return {
        "state": "planned",
        "authorized": True,
        "reason": "authorized and sandboxed; the plan is ready, no process started",
        "sandbox": spec.name,
        "plan": plan.as_dict(),
        "diagnostics": [],
    }


def _sandbox_by_name(name: str) -> SandboxSpec | None:
    """The sandbox primitive with that name, if the host has it installed."""
    detected = detect_sandbox()
    if detected is not None and detected.name == name:
        return detected
    import shutil

    if not shutil.which(name):
        return None
    if name == "bwrap":
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
            ),
        )
    if name == "firejail":
        return SandboxSpec(name="firejail", prefix=("firejail", "--quiet", "--net=none"))
    if name == "docker":
        return SandboxSpec(
            name="docker",
            prefix=(
                "docker", "run", "--rm", "-i", "--network", "none",
                "--read-only", "--cap-drop", "ALL",
            ),
        )
    if name == "unshare":
        return SandboxSpec(
            name="unshare",
            prefix=("unshare", "--user", "--map-root-user", "--net", "--mount"),
        )
    return None


def build_driver_plan(
    kind: str,
    target: Path,
    entrypoint: str,
    *,
    environment: dict[str, str] | None = None,
    timeout_seconds: int = 10,
    memory_mib: int = 512,
) -> CollectorSpec:
    """Describe the driver that would collect one kind of observation.

    The driver is a small program that loads the library and calls the
    entry point. This function only *describes* it: the command line is
    produced by :func:`spec_to_plan` and is never executed here.
    """
    if kind not in COLLECTOR_KINDS:
        raise CollectorUnavailable(f"Unknown collector kind: {kind}")

    merged = {
        "SOINSIGHT_TARGET": str(target),
        "SOINSIGHT_ENTRYPOINT": entrypoint,
        "SOINSIGHT_OUTPUT": f"{kind}.jsonl",
    }
    merged.update(environment or {})

    limits = {"timeout_seconds": timeout_seconds, "memory_mib": memory_mib}

    if kind == "trace":
        # The trace collector watches the library as a whole: the modules it
        # loads and the calls it makes, rather than one kind of observation.
        return CollectorSpec(
            kind=kind,
            driver="soinsight-trace-collector",
            entrypoint=entrypoint,
            environment=merged,
            arguments=("--trace", str(target)),
            instrumentation=("dlopen", "dlsym", "module-loads", "calls"),
            limits=limits,
            outputs=("trace.jsonl",),
        )
    if kind == "arguments":
        return CollectorSpec(
            kind=kind,
            driver="soinsight-arg-collector",
            entrypoint=entrypoint,
            environment=merged,
            arguments=("--arguments", str(target), entrypoint),
            instrumentation=("entry-arguments", "return-value"),
            limits=limits,
            outputs=("arguments.jsonl",),
        )
    if kind == "memory":
        return CollectorSpec(
            kind=kind,
            driver="soinsight-memory-collector",
            entrypoint=entrypoint,
            environment=merged,
            arguments=("--memory", str(target), entrypoint),
            instrumentation=("/proc/<pid>/maps", "heap", "stack"),
            limits=limits,
            outputs=("memory.jsonl",),
        )
    if kind == "syscalls":
        return CollectorSpec(
            kind=kind,
            driver="soinsight-syscall-collector",
            entrypoint=entrypoint,
            environment=merged,
            arguments=("--syscalls", str(target), entrypoint),
            instrumentation=("ptrace", "seccomp-filter"),
            limits=limits,
            outputs=("syscalls.jsonl",),
        )
    return CollectorSpec(
        kind="coverage",
        driver="soinsight-coverage-collector",
        entrypoint=entrypoint,
        environment=merged,
        arguments=("--coverage", str(target), entrypoint),
        instrumentation=("basic-blocks", "edges"),
        limits=limits,
        outputs=("coverage.jsonl",),
    )


def spec_to_plan(spec: CollectorSpec, sandbox: SandboxSpec) -> dict:
    """The sandboxed command line that would run the collector."""
    argv = [spec.driver, *spec.arguments]
    request = ExecutionRequest(
        target=Path(spec.environment.get("SOINSIGHT_TARGET", "")),
        argv=tuple(argv),
        timeout_seconds=int(spec.limits.get("timeout_seconds", 10)),
        memory_mib=int(spec.limits.get("memory_mib", 512)),
        environment=dict(spec.environment),
    )
    return DryRunExecutor(sandbox).plan(request).as_dict()


def dlopen_harness_source(
    library: str,
    entrypoint: str,
    *,
    arguments: tuple[str, ...] = (),
) -> str:
    """C source of a driver that loads the library and calls one function.

    The harness is the piece the dynamic collectors need: a shared object
    cannot be executed on its own, so something has to ``dlopen`` it and
    reach an entry point. The source is a template -- it declares the entry
    point by hand, because a recovered signature is a fact, not a C
    prototype that is guaranteed to compile.
    """
    signature = " ".join(arguments) if arguments else "void *"
    return "\n".join(
        [
            "/* Generated by SOInsight dynamic.* -- a template driver, not a",
            " * finished harness: declare the entry point yourself and adapt",
            " * the argument list before compiling.",
            " */",
            "#include <dlfcn.h>",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "",
            f'#define SOINSIGHT_LIBRARY "{library}"',
            f'#define SOINSIGHT_ENTRYPOINT "{entrypoint}"',
            "",
            "/* Declare the recovered entry point here, for example:",
            " * extern int parse(const unsigned char *buf, size_t len);",
            " */",
            f"typedef {signature} (*soinsight_entrypoint_t)(void);",
            "",
            "int main(int argc, char **argv) {",
            "    (void)argc;",
            "    (void)argv;",
            "    void *handle = dlopen(SOINSIGHT_LIBRARY, RTLD_NOW | RTLD_LOCAL);",
            "    if (handle == NULL) {",
            '        fprintf(stderr, "dlopen failed: %s\\n", dlerror());',
            "        return 2;",
            "    }",
            "    dlerror();",
            "    void *symbol = dlsym(handle, SOINSIGHT_ENTRYPOINT);",
            "    const char *error = dlerror();",
            "    if (error != NULL) {",
            '        fprintf(stderr, "dlsym failed: %s\\n", error);',
            "        return 3;",
            "    }",
            "    /* Call the entry point with the arguments the harness needs. */",
            "    /* soinsight_entrypoint_t entry = (soinsight_entrypoint_t)symbol; */",
            "    /* entry(); */",
            "    dlclose(handle);",
            "    return 0;",
            "}",
            "",
        ]
    )
