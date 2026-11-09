"""Cross-function taint propagation over the recovered call graph.

The intra-procedural pass in :mod:`soinsight.infrastructure.dataflow` knows
which registers hold a value derived from a function's own arguments. This
module connects that to the program as a whole:

1. a **source** function (from the taint library) contributes taint -- its
   return value, or the buffer its argument points at;
2. the value travels through the calling function's registers;
3. when the calling function passes a tainted value to a **sink**, the sink
   is reached with tainted data.

The analysis is deliberately conservative about what it claims. It follows
the calling convention, not the full calling graph: a tainted value in
``rdi`` is passed in ``rdi``. It never guesses that a pointer argument
aliases a buffer, and it never claims a value is *not* tainted. The claim
it makes is "the data reaching this sink came from that source", which is
a statement about a path, not about exploitability.

The scope is one call level deep: a source's result reaches a sink through
the function that called the source. Longer paths are reported as the
intermediate call, not chased to the end.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "TaintPath",
    "TaintFinding",
    "analyse_taint_paths",
]


@dataclass(frozen=True)
class TaintPath:
    """One path from a source to a sink."""

    source: str
    """The source function's identifier from the library."""
    source_symbol: str
    """The linkage name of the source function."""
    sink: str
    """The sink function's identifier from the library."""
    sink_symbol: str
    """The linkage name of the sink function."""
    call_site: int
    """Where the sink is called."""
    caller: str
    """The function that makes the call."""
    register: str
    """The register that carried the tainted value into the sink."""
    depth: int
    """How many definitions away from the source the value is."""
    kind: str
    """How the source contributed: ``return`` or ``argument``."""
    cwe: str = ""
    severity: str = "high"
    category: str = ""

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "source_symbol": self.source_symbol,
            "sink": self.sink,
            "sink_symbol": self.sink_symbol,
            "call_site": hex(self.call_site),
            "caller": self.caller,
            "register": self.register,
            "depth": self.depth,
            "kind": self.kind,
            "cwe": self.cwe,
            "severity": self.severity,
            "category": self.category,
        }

    def fingerprint(self) -> str:
        """A stable identity for the path, used to deduplicate."""
        return (
            f"taint:{self.source}:{self.sink}:{self.call_site:x}:{self.caller}"
        )


@dataclass(frozen=True)
class TaintFinding:
    """A sink reached by tainted data."""

    path: TaintPath
    message: str = ""

    def as_dict(self) -> dict:
        payload = self.path.as_dict()
        payload["message"] = self.message
        return payload


def analyse_taint_paths(
    *,
    library,
    symbols,
    callgraph,
    dataflow,
) -> tuple[TaintPath, ...]:
    """Find the sinks that are reached by tainted data.

    ``symbols`` is the ``basic.symbols`` result data, ``callgraph`` the
    ``basic.callgraph`` result data and ``dataflow`` the ``basic.dataflow``
    result data. Every one of them may be missing or incomplete; the
    analysis then simply finds fewer paths.
    """
    if library is None or library.is_empty:
        return ()

    exported = _exported_functions(symbols)
    if not exported:
        return ()

    flows = _taint_by_function(dataflow)
    external = _external_calls(callgraph)
    if not flows or not external:
        return ()

    paths: list[TaintPath] = []
    for function_name, records in flows.items():
        # The source contributions of this function, keyed by the register the
        # tainted value sits in.
        contributions = _source_contributions(records, library, exported)
        if not contributions:
            continue
        for call in external:
            sink = library.find_sink(call["name"])
            if sink is None:
                continue
            for record in records:
                if record["kind"] != "call-argument":
                    continue
                # The call site is an integer and the taint record carries
                # the address as text, so both are normalized before they
                # are compared.
                if call["address"] != _address_of(record.get("address")):
                    continue
                # The tainted value must be in the register that is handed to
                # the sink. A copy of the source into another register is
                # what makes the value reach the sink, so the contribution is
                # followed through the copies of that register.
                contribution = _contribution_for(contributions, record)
                if contribution is None:
                    continue
                paths.append(
                    TaintPath(
                        source=contribution["source"],
                        source_symbol=contribution["symbol"],
                        sink=sink.name,
                        sink_symbol=call["name"],
                        call_site=call["address"],
                        caller=function_name,
                        register=record.get("target") or "",
                        depth=record["depth"],
                        kind=contribution["kind"],
                        cwe=sink.cwe,
                        severity=sink.severity,
                        category=sink.category,
                    )
                )

    unique: dict[str, TaintPath] = {}
    for path in paths:
        unique.setdefault(path.fingerprint(), path)
    return tuple(unique.values())


def _exported_functions(symbols) -> dict[str, dict]:
    """The exported functions, indexed by their linkage name."""
    exported: dict[str, dict] = {}
    for record in (symbols or {}).get("functions") or ():
        linkage = str(record.get("name") or "")
        if not linkage:
            continue
        exported.setdefault(
            linkage,
            {
                "name": linkage,
                "demangled": record.get("demangled"),
                "signature": record.get("signature"),
            },
        )
    return exported


def _taint_by_function(dataflow) -> dict[str, list[dict]]:
    """The taint records of each function, indexed by function name."""
    flows: dict[str, list[dict]] = {}
    for function in (dataflow or {}).get("functions") or ():
        name = str(function.get("name") or "")
        if not name:
            continue
        records = [
            record
            for record in function.get("taint_flows") or ()
            if isinstance(record, dict)
        ]
        if records:
            flows.setdefault(name, []).extend(records)
    return flows


def _external_calls(callgraph) -> list[dict]:
    """Every call to a function outside the image, with its addresses."""
    calls: list[dict] = []
    for entry in (callgraph or {}).get("external_calls") or ():
        name = str(entry.get("name") or "")
        if not name:
            continue
        for site in entry.get("call_sites") or ():
            try:
                address = int(str(site), 0)
            except (TypeError, ValueError):
                continue
            calls.append({"name": name, "address": address})
    return calls


def _source_contributions(
    records: list[dict],
    library,
    exported: dict[str, dict],
) -> dict[str, dict]:
    """Which register holds the value of which source, in this function.

    A source contributes in two ways:

    * ``return`` -- the source function's return value lands in the first
      return register, and the caller may keep it in any register, so the
      contribution is matched against the register the *call* to the source
      left behind;
    * ``argument`` -- the source function writes into a buffer the caller
      passed, so the tainted register is the one that carried the buffer
      pointer.
    """
    contributions: dict[str, dict] = {}

    for record in records:
        kind = record.get("kind")
        if kind == "source-return":
            source = _match_source(library, exported, record.get("origin"))
            if source is None:
                continue
            contributions[record["target"]] = {
                "source": source.name,
                "symbol": str(record.get("origin") or ""),
                "kind": "return",
            }
        elif kind == "source-argument":
            source = _match_source(library, exported, record.get("origin"))
            if source is None:
                continue
            contributions[record["target"]] = {
                "source": source.name,
                "symbol": str(record.get("origin") or ""),
                "kind": "argument",
            }
    return contributions


def _match_source(library, exported: dict[str, dict], symbol: str):
    """The library source that matches a symbol, if any.

    The symbol is usually an imported function, so it is not in the
    exported table; the demangled name is then unavailable and the linkage
    name is matched on its own.
    """
    if not symbol:
        return None
    record = exported.get(symbol)
    demangled = str((record or {}).get("demangled") or "")
    return library.find_source(symbol, demangled)


def _contribution_for(contributions: dict[str, dict], record: dict) -> dict | None:
    """The source that reaches a sink call through the given register.

    The source landed in one register; the value may have been copied into
    others before the sink call. The copies are recorded in the same taint
    records, so the register the sink receives is looked up first, and the
    source that reached it is taken from the copy chain.
    """
    direct = contributions.get(record.get("target") or "")
    if direct is not None:
        return direct
    # The record's own source names the origin when it is a copy.
    origin = str(record.get("source") or "")
    for contribution in contributions.values():
        if contribution["symbol"] == origin or contribution["source"] == origin:
            return contribution
    return None


def _address_of(value) -> int:
    """The address as an integer, whether it is text or already a number."""
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return -1
