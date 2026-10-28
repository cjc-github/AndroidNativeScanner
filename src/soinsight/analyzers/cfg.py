"""``basic.cfg``: basic blocks, edges and loop structure per function."""

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
from ..infrastructure.elf import ElfFormatError, parse_elf

ANALYZER_ID = "basic.cfg"

_DEFAULT_OPTIONS = {
    "max_functions": 2000,
    "max_instructions": 50000,
}

_SOURCE_LABELS = {"symbols": "符号", "prologue": "序言扫描"}


class BasicCfgAnalyzer(Analyzer):
    """Split decoded functions into basic blocks and recover their edges."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="CFG Analyzer",
        version="1.0.0",
        description="Recover basic blocks, control-flow edges and loops.",
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
                    code="CFG_NO_DECODER",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Capstone is not installed; control flow cannot be "
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
                    code="CFG_NO_CODE_REGIONS",
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
                "function_count": len(functions),
                "block_count": sum(item["block_count"] for item in functions),
                "edge_count": sum(item["edge_count"] for item in functions),
                "loop_count": sum(item["loop_count"] for item in functions),
                "functions": functions,
                "truncated": truncated,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format control-flow facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 控制流图 ===",
            f"架构: {data.get('machine', 'N/A')}"
            f"（解码器: {data.get('decoder') or '不可用'}）",
            f"函数: {data.get('function_count', 0):,} 个",
            f"基本块: {data.get('block_count', 0):,} 个",
            f"边: {data.get('edge_count', 0):,} 条",
            f"回边环: {data.get('loop_count', 0):,} 个",
        ]
        if data.get("truncated"):
            lines.append("注意: 函数列表已按上限截断")
        functions = data.get("functions", [])
        if functions:
            lines.append("")
            lines.append("函数（按块数，前 12 个）:")
            ranked = sorted(
                functions, key=lambda item: (-item["block_count"], item["address"])
            )
            for function in ranked[:12]:
                lines.append(
                    f"  {function['address']:>10}  块 {function['block_count']:>4}"
                    f"  边 {function['edge_count']:>4}"
                    f"  环 {function['loop_count']:>3}"
                    f"  [{_SOURCE_LABELS.get(function['source'], function['source'])}]"
                    f" {function['name']}"
                )
        return "\n".join(lines)


def _empty_data(machine: str, decoder: str | None) -> dict:
    return {
        "machine": machine,
        "decoder": decoder,
        "function_count": 0,
        "block_count": 0,
        "edge_count": 0,
        "loop_count": 0,
        "functions": [],
        "truncated": False,
    }


def _collect(path, elf, regions, options: dict, diagnostics: list) -> tuple[list, bool]:
    """Build one CFG per function, honouring the instruction budget."""
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
        blob = _region_bytes(data, region)
        if blob is None:
            continue
        for address in disasm_layer.prologue_starts(
            blob, region.address, arch, 4 if arch == "aarch64" else 1, known
        ):
            starts.append((address, f"sub_{address:x}", 0, "prologue"))
            known.add(address)
    starts.sort(key=lambda item: item[0])

    functions: list[dict] = []
    budget = options["max_instructions"]
    truncated = False
    for index, (address, name, size, source) in enumerate(starts):
        if len(functions) >= options["max_functions"]:
            truncated = True
            diagnostics.append(
                Diagnostic(
                    code="CFG_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"Function list truncated at {options['max_functions']} entries."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
            break
        if index + 1 < len(starts):
            extent = starts[index + 1][0] - address
        else:
            extent = _region_end(regions, address) - address
        if source == "symbols" and size > 0:
            extent = size
        if extent <= 0:
            continue
        blob = _extent_bytes(data, regions, address, extent)
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
                    code="CFG_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Instruction budget exhausted at "
                        f"{options['max_instructions']} entries."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
        budget -= len(decoded)

        graph = build_cfg(
            (item.address, item.size, item.mnemonic, item.op_str) for item in decoded
        )
        functions.append(
            {
                "name": name,
                "address": hex(address),
                "size": extent,
                "source": source,
                "instruction_count": len(decoded),
                "block_count": graph.block_count,
                "edge_count": graph.edge_count,
                "loop_count": len(graph.loops),
                "blocks": [
                    {
                        "start": hex(block.start),
                        "end": hex(block.end),
                        "terminator": block.terminator,
                        "successors": [hex(item) for item in block.successors],
                    }
                    for block in graph.blocks
                ],
                "edges": [
                    {
                        "source": hex(source_address),
                        "target": hex(target_address),
                        "kind": kind,
                    }
                    for source_address, target_address, kind in graph.edges
                ],
                "loops": [[hex(item) for item in cycle] for cycle in graph.loops],
            }
        )
    return functions, truncated


def _region_bytes(data: bytes, region) -> bytes | None:
    if region.offset + region.size <= len(data):
        return data[region.offset : region.offset + region.size]
    if region.offset < len(data):
        return data[region.offset :]
    return None


def _extent_bytes(data: bytes, regions, address: int, size: int) -> bytes | None:
    """File bytes covering ``[address, address + size)`` of a code region."""
    for region in regions:
        region_end = region.address + region.size
        if region.address <= address < region_end:
            offset = region.offset + (address - region.address)
            available = min(size, region_end - address)
            return _region_bytes(data, region.__class__(
                index=region.index,
                name=region.name,
                type=region.type,
                type_value=region.type_value,
                flags=region.flags,
                address=region.address,
                offset=offset,
                size=available,
                link=region.link,
                info=region.info,
                alignment=region.alignment,
                entry_size=region.entry_size,
            ))
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
    for key in ("max_functions", "max_instructions"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, min(value, 1_000_000))
    return resolved
