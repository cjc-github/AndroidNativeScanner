"""Compiler and toolchain identification from link-level evidence.

Toolchains leave a trail in a native image: the ``.comment`` section holds the
compiler banner (``GCC: (GNU) 9.4.0``, ``Android clang version 14.0.6``,
``rustc 1.63.0``), an ``.note.android.ident`` note marks an NDK build, the
GNU/ABI tags name the OS and ABI, and runtime symbols (``__cxa_throw``,
``_Unwind_Resume``, ``__aeabi_*``) reveal the runtime the code links against.

The module is signature-driven: a toolchain is reported only when a concrete
banner, note or symbol family matched, and every match carries the evidence it
was based on. Version numbers are extracted from the matching banner when a
pattern is known; the ``strength`` field separates single-source matches from
corroborated ones, and the whole report stays on the fact side.
"""

import re
from dataclasses import dataclass

__all__ = ["ToolchainEvidence", "ToolchainHit", "identify"]

_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}")


@dataclass(frozen=True)
class ToolchainEvidence:
    """One fingerprint that matched a toolchain."""

    source: str
    """Where the evidence came from (``comment``, ``note``, ``symbol``)."""

    detail: str
    """The concrete fingerprint, for the report and the text renderer."""


@dataclass(frozen=True)
class ToolchainHit:
    """A toolchain identification, with every fingerprint that matched."""

    toolchain: str
    """Stable toolchain identifier (``gcc``, ``clang``, ``rust``, ...)."""

    family: str
    """Grouping: ``c``, ``c++``, ``rust``, ``swift``, ``ndk``, ``wasm``."""

    version: str | None
    """Version extracted from the banner, when one is known."""

    strength: str
    """``single`` when one source matched, ``corroborated`` for two or more."""

    evidence: tuple[ToolchainEvidence, ...]
    """The fingerprints that hit."""


def _banner_line(text: str, banner: str) -> str | None:
    """Return the whole line that contains ``banner``."""
    for line in text.splitlines():
        if banner in line:
            return line
    return None


def identify(
    comment_text: str,
    note_text: str,
    symbol_names: tuple[str, ...],
) -> tuple[ToolchainHit, ...]:
    """Match compiler evidence against the toolchain fingerprint table."""
    hits: list[ToolchainHit] = []
    symbol_pool = frozenset(symbol_names)

    for fingerprint in _TOOLCHAINS:
        evidence: list[ToolchainEvidence] = []
        for banner in fingerprint.get("comments", ()):
            if banner in comment_text:
                # Keep the *line* that carried the banner, so the version
                # extraction sees ``GCC: (GNU) 9.4.0`` rather than the
                # fingerprint template ``GCC: (GNU)``.
                line = _banner_line(comment_text, banner)
                evidence.append(ToolchainEvidence("comment", line or banner))
        for note in fingerprint.get("notes", ()):
            if note in note_text:
                evidence.append(ToolchainEvidence("note", note))
        for symbol in fingerprint.get("symbols", ()):
            if any(name.startswith(symbol) for name in symbol_names):
                evidence.append(ToolchainEvidence("symbol", symbol))
        if not evidence:
            continue
        version = None
        for item in evidence:
            if item.source in ("comment", "note"):
                match = _VERSION_RE.search(item.detail)
                if match:
                    version = match.group(0)
                    break
        strength = "corroborated" if len(evidence) >= 2 else "single"
        hits.append(
            ToolchainHit(
                toolchain=fingerprint["toolchain"],
                family=fingerprint["family"],
                version=version,
                strength=strength,
                evidence=tuple(evidence),
            )
        )

    hits.sort(key=lambda item: (-len(item.evidence), item.toolchain))
    return tuple(hits)


_TOOLCHAINS: tuple[dict, ...] = (
    {
        "toolchain": "gcc",
        "family": "c",
        "comments": (
            "GCC: (GNU)",
            "GCC: (Ubuntu",
            "GCC: (Debian",
            "gcc (GCC)",
        ),
        "notes": ("GNU",),
        "symbols": ("_Unwind_Resume", "_Unwind_Backtrace", "__aeabi_unwind_cpp_pr0"),
    },
    {
        "toolchain": "clang",
        "family": "c",
        "comments": (
            "clang version",
            "Android clang version",
            "Apple LLVM version",
            "clang++ version",
        ),
        "notes": (),
        "symbols": ("__clang_call_terminate",),
    },
    {
        "toolchain": "rust",
        "family": "rust",
        "comments": ("rustc ", "rust version", "Rust "),
        "notes": (),
        "symbols": ("_ZN4core3pan", "_ZN4core6panicking", "rust_eh_personality"),
    },
    {
        "toolchain": "swift",
        "family": "swift",
        "comments": ("Swift version", "swift-"),
        "notes": (),
        "symbols": ("swift_release", "_T0s5print", "_swift_"),
    },
    {
        "toolchain": "android-ndk",
        "family": "ndk",
        "comments": ("Android clang version", "Android NDK"),
        "notes": ("Android",),
        "symbols": ("__android_log_print", "__android_log_write"),
    },
    {
        "toolchain": "emscripten",
        "family": "wasm",
        "comments": ("Emscripten", "emscripten "),
        "notes": (),
        "symbols": ("emscripten_asm_const_int",),
    },
    {
        "toolchain": "llvm",
        "family": "c",
        "comments": ("LLVM version", "LLVM ("),
        "notes": (),
        "symbols": (),
    },
    {
        "toolchain": "msvc",
        "family": "c++",
        "comments": ("Microsoft (R) C/C++ Optimizing Compiler", "Microsoft (R) C/C++"),
        "notes": (),
        "symbols": ("_msvcp_lock_file_scope",),
    },
)
