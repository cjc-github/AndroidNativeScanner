"""The taint function library: sources, sinks and propagators.

A *source* is a function whose return value (or whose arguments) carry data
that originates outside the program: a socket read, a command-line argument,
a file read. A *sink* is a function that passes such data on to somewhere
dangerous: a command execution, a format string, an unbounded copy.

The library is data, not code, so it can be replaced by the user: the
built-in table lives in ``configs/taint-functions.yaml`` and a project may
point the configuration at its own file. The format is deliberately small::

    version: 1
    sources:
      - name: recv
        match: recv
        kind: return
        cwe: CWE-20
        description: Reads bytes from a socket.
    sinks:
      - name: system
        match: system
        kind: argument
        argument: 0
        cwe: CWE-78
        severity: critical
        description: Passes its argument to the shell.

``match`` is a regular expression matched against the *linkage* name (the
mangled symbol), so ``^__isoc99_scanf`` and ``^recv$`` both work. A source
may be matched against the demangled name as well, which is what the
``match_demangled`` field selects.

The kinds are:

``return``
    The tainted value is the function's return value.
``argument``
    The tainted value is the argument at ``argument`` (0-based).
``argument_any``
    Any argument may carry the tainted value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

#: Compiled patterns, keyed by their source text. The dataclass is frozen,
#: so the cache lives outside it.
_PATTERN_CACHE: dict[str, re.Pattern] = {}

__all__ = [
    "DEFAULT_LIBRARY_PATH",
    "TaintFunction",
    "TaintLibrary",
    "TaintLibraryError",
    "load_taint_library",
    "parse_taint_library",
]


#: The built-in library, packaged with the code so an installed tool can
#: always find it.
PACKAGED_LIBRARY_PATH = Path(__file__).resolve().parent.parent / "configs" / "taint-functions.yaml"


def _default_library_path() -> Path:
    """The built-in table, wherever the installation keeps it.

    A checkout keeps it in ``configs/`` at the project root; an installed
    wheel carries it inside the package. Both are found, and the packaged
    copy wins when the checkout has none.
    """
    candidates = [
        PACKAGED_LIBRARY_PATH,
        Path(__file__).resolve().parents[3] / "configs" / "taint-functions.yaml",
        Path("configs/taint-functions.yaml"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return PACKAGED_LIBRARY_PATH


#: Where the built-in library ships.
DEFAULT_LIBRARY_PATH = _default_library_path()


class TaintLibraryError(ValueError):
    """The library file is missing or malformed."""


@dataclass(frozen=True)
class TaintFunction:
    """One source or sink."""

    name: str
    """The identifier used in reports."""

    match: str
    """A regular expression matched against the linkage name."""

    kind: str = "return"
    """``return``, ``argument`` or ``argument_any``."""

    argument: int = 0
    """Which argument carries the tainted value (``argument`` kind)."""

    match_demangled: bool = False
    """Match the demangled name instead of the linkage name."""

    severity: str = "high"
    """The severity a finding about this sink gets."""

    cwe: str = ""
    """The CWE the sink belongs to."""

    description: str = ""
    """What the function does, for the report."""

    category: str = ""
    """A grouping for the report (``io``, ``exec``, ``format`` ...)."""

    def compiled(self) -> re.Pattern:
        """The compiled pattern; the pattern is compiled once and cached."""
        cached = _PATTERN_CACHE.get(self.match)
        if cached is None:
            try:
                cached = re.compile(self.match)
            except re.error as exc:
                raise TaintLibraryError(
                    f"Invalid pattern for '{self.name}': {exc}"
                ) from exc
            _PATTERN_CACHE[self.match] = cached
        return cached

    def matches(self, linkage_name: str, demangled_name: str = "") -> bool:
        """Whether this function matches the given names."""
        candidate = demangled_name if self.match_demangled else linkage_name
        if not candidate:
            candidate = linkage_name or demangled_name
        if not candidate:
            return False
        try:
            return self.compiled().search(candidate) is not None
        except TaintLibraryError:
            return False

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "match": self.match,
            "kind": self.kind,
            "argument": self.argument,
            "match_demangled": self.match_demangled,
            "severity": self.severity,
            "cwe": self.cwe,
            "category": self.category,
            "description": self.description,
        }


@dataclass(frozen=True)
class TaintLibrary:
    """The sources and sinks the analysis knows about."""

    sources: tuple[TaintFunction, ...] = ()
    sinks: tuple[TaintFunction, ...] = ()
    propagators: tuple[TaintFunction, ...] = ()
    origin: str = ""
    """Where the library came from, for the report."""

    @property
    def is_empty(self) -> bool:
        return not (self.sources or self.sinks or self.propagators)

    def find_source(self, linkage_name: str, demangled_name: str = "") -> TaintFunction | None:
        for function in self.sources:
            if function.matches(linkage_name, demangled_name):
                return function
        return None

    def find_sink(self, linkage_name: str, demangled_name: str = "") -> TaintFunction | None:
        for function in self.sinks:
            if function.matches(linkage_name, demangled_name):
                return function
        return None

    def as_dict(self) -> dict:
        return {
            "origin": self.origin,
            "source_count": len(self.sources),
            "sink_count": len(self.sinks),
            "propagator_count": len(self.propagators),
            "sources": [item.as_dict() for item in self.sources],
            "sinks": [item.as_dict() for item in self.sinks],
            "propagators": [item.as_dict() for item in self.propagators],
        }


def _build(items: Iterable, section: str) -> tuple[TaintFunction, ...]:
    built: list[TaintFunction] = []
    for entry in items or ():
        if not isinstance(entry, dict):
            raise TaintLibraryError(
                f"Each entry of '{section}' must be a mapping, got {type(entry).__name__}"
            )
        name = str(entry.get("name") or "").strip()
        match = str(entry.get("match") or "").strip()
        if not name or not match:
            raise TaintLibraryError(
                f"Each entry of '{section}' needs a 'name' and a 'match'"
            )
        kind = str(entry.get("kind") or "return").strip().lower()
        if kind not in ("return", "argument", "argument_any"):
            raise TaintLibraryError(
                f"'{name}' has an unknown kind '{kind}'; use return, argument "
                "or argument_any"
            )
        argument = entry.get("argument", 0)
        try:
            argument = int(argument)
        except (TypeError, ValueError):
            raise TaintLibraryError(f"'{name}' has a non-integer 'argument'") from None
        if argument < 0:
            raise TaintLibraryError(f"'{name}' has a negative 'argument'")
        built.append(
            TaintFunction(
                name=name,
                match=match,
                kind=kind,
                argument=argument,
                match_demangled=bool(entry.get("match_demangled", False)),
                severity=str(entry.get("severity") or "high").strip().lower(),
                cwe=str(entry.get("cwe") or "").strip(),
                category=str(entry.get("category") or "").strip(),
                description=str(entry.get("description") or "").strip(),
            )
        )
    return tuple(built)


def parse_taint_library(payload: dict, *, origin: str = "") -> TaintLibrary:
    """Build a library from an already parsed document."""
    if not isinstance(payload, dict):
        raise TaintLibraryError("The taint library must be a mapping")
    version = payload.get("version")
    if version is not None and int(version) != 1:
        raise TaintLibraryError(
            f"Unsupported taint library version: {version}; this build reads version 1"
        )
    return TaintLibrary(
        sources=_build(payload.get("sources") or (), "sources"),
        sinks=_build(payload.get("sinks") or (), "sinks"),
        propagators=_build(payload.get("propagators") or (), "propagators"),
        origin=origin or str(payload.get("origin") or ""),
    )


def load_taint_library(path) -> TaintLibrary:
    """Read the library from a YAML file.

    A missing file is an error the caller reports; an empty library is a
    legitimate state (the analysis then finds no sources and no sinks).

    The value may also be the YAML document itself rather than a path. That
    keeps the table usable from a configuration value and from code, where
    a file would be an extra step.
    """
    text = str(path)
    if "\n" in text or text.lstrip().startswith("version:"):
        return _parse_text(text, origin="inline")

    location = Path(path).expanduser()
    if not location.is_file():
        raise TaintLibraryError(f"The taint library file does not exist: {location}")
    try:
        raw = location.read_text(encoding="utf-8")
    except OSError as exc:
        raise TaintLibraryError(f"Cannot read the taint library: {exc}") from exc
    return _parse_text(raw, origin=str(location))


def _parse_text(text: str, *, origin: str) -> TaintLibrary:
    """Parse a YAML document into a library."""
    import yaml

    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TaintLibraryError(f"The taint library is not valid YAML: {exc}") from exc
    if payload is None:
        payload = {}
    return parse_taint_library(payload, origin=origin)
