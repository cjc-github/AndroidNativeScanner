"""``dynamic.syscalls``: plan a runtime system-call interception.

The collector would run the library under a seccomp filter that denies
everything by default and lets through a small allow-list, so an unexpected
system call stops the run instead of succeeding quietly.

The static side of the capability is that policy plus the list of dangerous
APIs the library imports -- the calls worth watching when they do happen.
"""

from ..core.analyzer import AnalyzerMetadata
from .dynamic_collectors import DynamicCollectorAnalyzer

ANALYZER_ID = "dynamic.syscalls"

#: The system calls a collector run needs; everything else is denied.
_DEFAULT_ALLOWLIST = (
    "read",
    "write",
    "close",
    "fstat",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "sigaltstack",
    "exit_group",
    "futex",
)

#: System calls that are denied even when the allow-list is generous.
_BLOCKLIST = (
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone",
    "ptrace",
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    "bpf",
    "perf_event_open",
    "kexec_load",
)


class DynamicSyscallAnalyzer(DynamicCollectorAnalyzer):
    """Plan a sandboxed system-call interception."""

    collector_kind = "syscalls"

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Runtime Syscall Interception",
        version="1.0.0",
        description="Plan a sandboxed system-call interception with a default-deny filter.",
        requires=(),
        optional_requires=("security.dangerous-api",),
        default_enabled=True,
        cacheable=False,
    )

    def collect_facts(self, context) -> dict:
        watched: list[str] = []
        dangerous = context.optional("security.dangerous-api")
        if dangerous is not None:
            watched = [
                str(name)
                for name in (dangerous.data or {}).get("matched_apis") or ()
            ]
        return {
            "policy": {
                "default_action": "deny",
                "allowlist": list(_DEFAULT_ALLOWLIST),
                "blocklist": list(_BLOCKLIST),
            },
            "watched_apis": watched,
            "watched_api_count": len(watched),
        }

    def fact_lines(self, data: dict) -> list[tuple[str, object]]:
        return [
            ("过滤策略", "默认拒绝"),
            ("重点关注 API", f"{data.get('watched_api_count', 0)} 个"),
        ]
