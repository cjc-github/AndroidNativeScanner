"""``basic.dataflow``: intra-procedural use-def and reaching definitions."""

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
from ..infrastructure.cfg import build_cfg
from ..infrastructure.dataflow import analyse
from ..infrastructure.elf import ElfFormatError, parse_elf

ANALYZER_ID = "basic.dataflow"

_DEFAULT_OPTIONS = {
    "max_functions": 500,
    "max_instructions": 20000,
    "max_pairs": 20000,
}

_SOURCE_LABELS = {"symbols": "符号", "prologue": "序言扫描"}


class BasicDataflowAnalyzer(Analyzer):
    """Report per-block use-def chains and reaching definitions per function."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Data Flow Analyzer",
        version="1.0.0",
        description="Recover intra-procedural use-def and reaching definitions.",
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
                    code="DATAFLOW_NO_DECODER",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Capstone is not installed; data flow cannot be "
                        "recovered (pip install capstone)."
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

        regions = disasm_layer.executable_sections(elf)
        if not regions:
            diagnostics.append(
                Diagnostic(
                    code="DATAFLOW_NO_CODE_REGIONS",
                    level=DiagnosticLevel.WARNING,
                    message="No executable section with an address is present.",
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

        functions, truncated = _collect(
            target.real_path, elf, regions, options, diagnostics
        )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "machine": elf.header.machine,
                "decoder": decoder_version,
                "scope": "intra-procedural",
                "function_count": len(functions),
                "block_count": sum(item["block_count"] for item in functions),
                "def_count": sum(item["def_count"] for item in functions),
                "use_count": sum(item["use_count"] for item in functions),
                "reaching_pair_count": sum(
                    item["reaching_pair_count"] for item in functions
                ),
                "functions": functions,
                "truncated": truncated,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format data-flow facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 数据流 ===",
            f"架构: {data.get('machine', 'N/A')}"
            f"（解码器: {data.get('decoder') or '不可用'}）",
            f"范围: {data.get('scope', 'N/A')}（函数内）",
            f"函数: {data.get('function_count', 0):,} 个",
            f"基本块: {data.get('block_count', 0):,} 个",
            f"定义: {data.get('def_count', 0):,} 个",
            f"使用: {data.get('use_count', 0):,} 个",
            f"到达定义对: {data.get('reaching_pair_count', 0):,} 对",
        ]
        if data.get("truncated"):
            lines.append("注意: 函数或定义对已按上限截断")
        functions = data.get("functions", [])
        if functions:
            lines.append("")
            lines.append("函数（按到达定义对，前 12 个）:")
            ranked = sorted(
                functions,
                key=lambda item: (-item["reaching_pair_count"], item["address"]),
            )
            for function in ranked[:12]:
                lines.append(
                    f"  {function['address']:>10}  块 {function['block_count']:>4}"
                    f"  定义 {function['def_count']:>4}"
                    f"  使用 {function['use_count']:>4}"
                    f"  对 {function['reaching_pair_count']:>5}"
                    f"  [{_SOURCE_LABELS.get(function['source'], function['source'])}]"
                    f" {function['name']}"
                )
        return "\n".join(lines)


def _empty_data(machine: str, decoder: str | None) -> dict:
    return {
        "machine": machine,
        "decoder": decoder,
        "scope": "intra-procedural",
        "function_count": 0,
        "block_count": 0,
        "def_count": 0,
        "use_count": 0,
        "reaching_pair_count": 0,
        "functions": [],
        "truncated": False,
    }


def _collect(path, elf, regions, options: dict, diagnostics: list) -> tuple[list, bool]:
    """Build one data-flow result per function, honouring the budgets."""
    data = path.read_bytes()
    arch = disasm_layer.arch_name(elf.header.machine)
    arch_pair = disasm_layer.decode_architecture(elf.header.machine)
    mode = arch_pair[1] if arch_pair else 0

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

    functions: list[dict] = []
    budget = options["max_instructions"]
    truncated = len(starts) > options["max_functions"]
    if truncated:
        diagnostics.append(
            Diagnostic(
                code="DATAFLOW_TRUNCATED",
                level=DiagnosticLevel.WARNING,
                message=(
                    f"Function list truncated at {options['max_functions']} entries."
                ),
                analyzer_id=ANALYZER_ID,
            )
        )

    for index, (address, name, size, source) in enumerate(
        starts[: options["max_functions"]]
    ):
        if size <= 0:
            if index + 1 < len(starts):
                size = starts[index + 1][0] - address
            else:
                size = _region_end(regions, address) - address
        if size <= 0:
            continue
        blob = _extent_bytes(data, regions, address, size)
        if blob is None:
            continue
        decoded = disasm_layer.decode_bytes(blob, address, arch_pair[0], mode)
        if not decoded:
            continue
        if len(decoded) > budget:
            decoded = decoded[:budget]
            truncated = True
            diagnostics.append(
                Diagnostic(
                    code="DATAFLOW_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Instruction budget exhausted at "
                        f"{options['max_instructions']} entries."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
        budget -= len(decoded)

        records = [
            (item.address, item.size, item.mnemonic, item.op_str) for item in decoded
        ]
        graph = build_cfg(records)
        flow = analyse(records, graph, arch, options["max_pairs"])
        functions.append(
            {
                "name": name,
                "address": hex(address),
                "size": size,
                "source": source,
                "instruction_count": len(decoded),
                "block_count": graph.block_count,
                "def_count": flow.def_count,
                "use_count": flow.use_count,
                "reaching_pair_count": flow.reaching_pairs,
                "blocks": [
                    {
                        "start": hex(block.start),
                        "defs": [
                            {"location": item.location, "address": hex(item.address)}
                            for item in block.defs
                        ],
                        "uses": [
                            {
                                "location": item.location,
                                "address": hex(item.address),
                                "reaching": [
                                    {"location": definition.location,
                                     "address": hex(definition.address)}
                                    for definition in item.reaching
                                ],
                            }
                            for item in block.uses
                        ],
                    }
                    for block in flow.blocks
                ],
            }
        )
    return functions, truncated


def _extent_bytes(data: bytes, regions, address: int, size: int) -> bytes | None:
    """File bytes covering ``[address, address + size)`` of a code region."""
    for region in regions:
        region_end = region.address + region.size
        if region.address <= address < region_end:
            offset = region.offset + (address - region.address)
            available = min(size, region_end - address)
            if offset < 0 or offset + available > len(data):
                return None
            return data[offset : offset + available]
    return None


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
    for key in ("max_functions", "max_instructions", "max_pairs"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, min(value, 1_000_000))
    return resolved
