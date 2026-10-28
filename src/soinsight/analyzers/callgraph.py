"""``basic.callgraph``: direct calls, PLT resolution and external calls."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure import disasm as disasm_layer
from ..infrastructure.callgraph import build_call_graph
from ..infrastructure.elf import ElfFormatError, parse_elf

ANALYZER_ID = "basic.callgraph"

_DEFAULT_OPTIONS = {
    "max_functions": 2000,
    "max_instructions": 50000,
    "max_edges": 20000,
}

_KIND_LABELS = {
    "local": "本地",
    "import": "导入",
    "indirect": "间接",
}


class BasicCallgraphAnalyzer(Analyzer):
    """Resolve call sites into caller/callee edges with an external-call list."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Call Graph Analyzer",
        version="1.0.0",
        description="Resolve direct calls, PLT imports and indirect call sites.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []
        try:
            elf = parse_elf(target.real_path)
        except ElfFormatError as exc:
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[
                    Diagnostic(
                        code="INVALID_ELF",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                        analyzer_id=ANALYZER_ID,
                    )
                ],
            )

        decoder_version = disasm_layer.capstone_version()
        if decoder_version is None:
            diagnostics.append(
                Diagnostic(
                    code="CALLGRAPH_NO_DECODER",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Capstone is not installed; call sites cannot be "
                        "resolved (pip install capstone)."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.SUCCESS,
                data=_empty_data(elf.header.machine, decoder_version),
                diagnostics=diagnostics,
            )

        data = _collect(
            target.real_path, elf, options, diagnostics, decoder_version
        )
        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data=data,
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format call-graph facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 调用图 ===",
            f"架构: {data.get('machine', 'N/A')}"
            f"（解码器: {data.get('decoder') or '不可用'}）",
            f"调用边: {data.get('edge_count', 0):,} 条"
            f"（本地 {data.get('local_count', 0):,} /"
            f" 导入 {data.get('import_count', 0):,} /"
            f" 间接 {data.get('indirect_count', 0):,}）",
            f"被调函数: {data.get('callee_count', 0):,} 个",
        ]
        if data.get("truncated"):
            lines.append("注意: 调用边已按上限截断")
        imports = data.get("external_calls", [])
        if imports:
            lines.append("")
            lines.append("外部调用（按调用点数，前 12 个）:")
            for entry in imports[:12]:
                lines.append(
                    f"  {entry['name']:<28} 调用点 {entry['call_site_count']:>4}"
                    f"  PLT {entry['plt_address']}"
                )
        return "\n".join(lines)


def _empty_data(machine: str, decoder: str | None) -> dict:
    return {
        "machine": machine,
        "decoder": decoder,
        "edge_count": 0,
        "local_count": 0,
        "import_count": 0,
        "indirect_count": 0,
        "callee_count": 0,
        "call_edges": [],
        "external_calls": [],
        "truncated": False,
    }


def _collect(path, elf, options: dict, diagnostics: list, decoder: str) -> dict:
    """Build the call graph and derive the external-call summary."""
    data = path.read_bytes()
    regions = disasm_layer.executable_sections(elf)
    if not regions:
        diagnostics.append(
            Diagnostic(
                code="CALLGRAPH_NO_CODE_REGIONS",
                level=DiagnosticLevel.WARNING,
                message="No executable section with an address is present.",
                analyzer_id=ANALYZER_ID,
            )
        )
        return _empty_data(elf.header.machine, decoder)

    arch = disasm_layer.arch_name(elf.header.machine)
    starts: list[tuple[int, str, int, str]] = []
    known: set[int] = set()
    for name, address, size, table in disasm_layer.symbol_functions(elf):
        starts.append((address, name, size, "symbols"))
        known.add(address)
    for region in regions:
        blob = data[region.offset : region.offset + region.size]
        for address in disasm_layer.prologue_starts(
            blob, region.address, arch, 4 if arch == "aarch64" else 1, known
        ):
            starts.append((address, f"sub_{address:x}", 0, "prologue"))
            known.add(address)
    starts.sort(key=lambda item: item[0])

    # Bound each function so decoding stops at the next boundary, and emit
    # ``(name, address, size, source)`` records for the graph builder.
    bounded: list[tuple[str, int, int, str]] = []
    for index, (address, name, size, source) in enumerate(starts):
        if size <= 0:
            if index + 1 < len(starts):
                size = starts[index + 1][0] - address
            else:
                size = _region_end(regions, address) - address
        bounded.append((name, address, max(size, 0), source))

    graph = build_call_graph(
        data, elf, bounded[: options["max_functions"]],
        disasm_layer.decode_architecture,
    )

    edges = graph.edges
    truncated = len(bounded) > options["max_functions"]
    if len(edges) > options["max_edges"]:
        edges = edges[: options["max_edges"]]
        truncated = True
    if truncated:
        diagnostics.append(
            Diagnostic(
                code="CALLGRAPH_TRUNCATED",
                level=DiagnosticLevel.WARNING,
                message=(
                    "Call graph truncated at "
                    f"{options['max_functions']} functions / "
                    f"{options['max_edges']} edges."
                ),
                analyzer_id=ANALYZER_ID,
            )
        )

    external = _external_calls(edges)
    return {
        "machine": elf.header.machine,
        "decoder": decoder,
        "edge_count": len(edges),
        "local_count": sum(1 for edge in edges if edge.kind == "local"),
        "import_count": sum(1 for edge in edges if edge.kind == "import"),
        "indirect_count": sum(1 for edge in edges if edge.kind == "indirect"),
        "callee_count": len(graph.callers_of),
        "call_edges": [
            {
                "caller": hex(edge.caller),
                "callee": hex(edge.callee) if edge.callee is not None else None,
                "callee_name": edge.callee_name,
                "kind": edge.kind,
            }
            for edge in edges
        ],
        "external_calls": external,
        "truncated": truncated,
    }


def _external_calls(edges) -> list[dict]:
    """Aggregate import edges into one record per imported symbol."""
    sites: dict[str, list[int]] = {}
    addresses: dict[str, int] = {}
    for edge in edges:
        if edge.kind != "import" or not edge.callee_name:
            continue
        sites.setdefault(edge.callee_name, []).append(edge.caller)
        addresses.setdefault(edge.callee_name, edge.callee or 0)
    return [
        {
            "name": name,
            "plt_address": hex(addresses[name]),
            "call_site_count": len(callers),
            "call_sites": [hex(item) for item in sorted(set(callers))],
        }
        for name, callers in sorted(sites.items(), key=lambda item: -len(item[1]))
    ]


def _region_end(regions, address: int) -> int:
    """End of the executable region containing ``address``."""
    for region in regions:
        if region.address <= address < region.address + region.size:
            return region.address + region.size
    return address


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_functions", "max_instructions", "max_edges"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, min(value, 1_000_000))
    return resolved
