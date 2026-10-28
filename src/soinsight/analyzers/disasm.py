"""``basic.disasm``: instruction decoding, function bounds and code regions."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.disasm import (
    arch_name,
    capstone_version,
    decode_architecture,
    decode_bytes,
    executable_sections,
    prologue_starts,
    symbol_functions,
)
from ..infrastructure.elf import ElfFormatError, parse_elf

ANALYZER_ID = "basic.disasm"

_DEFAULT_OPTIONS = {
    "max_functions": 10000,
    "max_instructions": 20000,
}


class BasicDisasmAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Disassembly Analyzer",
        version="1.0.0",
        description=(
            "Decode executable sections, recover function boundaries and "
            "list code regions."
        ),
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

        arch_pair = decode_architecture(elf.header.machine)
        arch = arch_name(elf.header.machine)
        if arch is None:
            diagnostics.append(
                Diagnostic(
                    code="DISASM_UNSUPPORTED_ARCH",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"No decoder for machine {elf.header.machine}; "
                        "boundaries only."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
        regions = executable_sections(elf)
        if not regions:
            diagnostics.append(
                Diagnostic(
                    code="DISASM_NO_CODE_REGIONS",
                    level=DiagnosticLevel.WARNING,
                    message="No executable section with an address is present.",
                    analyzer_id=ANALYZER_ID,
                )
            )
        decoder_version = capstone_version()
        if decoder_version is None:
            diagnostics.append(
                Diagnostic(
                    code="DISASM_DECODER_UNAVAILABLE",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Capstone is not installed; instructions are not "
                        "decoded (pip install capstone)."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        functions, instructions, truncated = _collect(
            target.real_path, elf, arch, arch_pair, regions, options, diagnostics
        )
        symbol_bounds = [
            item for item in functions if item["source"] == "symbols"
        ]

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "machine": elf.header.machine,
                "arch": arch,
                "decoder": decoder_version,
                "code_region_count": len(regions),
                "code_regions": [
                    {
                        "name": region.name,
                        "address": hex(region.address),
                        "offset": hex(region.offset),
                        "size": region.size,
                    }
                    for region in regions
                ],
                "function_count": len(functions),
                "symbol_function_count": len(symbol_bounds),
                "functions": functions,
                "instruction_count": len(instructions),
                "instructions": instructions,
                "truncated": truncated,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format disassembly facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 反汇编 ===",
            f"架构: {data.get('machine', 'N/A')}"
            f"（解码器: {data.get('decoder') or '不可用'}）",
            f"代码区域: {data.get('code_region_count', 0)} 个"
            f"（{', '.join(r['name'] for r in data.get('code_regions', []))}）",
            f"函数边界: {data.get('function_count', 0):,} 个"
            f"（符号 {data.get('symbol_function_count', 0):,} 个）",
            f"指令: {data.get('instruction_count', 0):,} 条",
        ]
        if data.get("truncated"):
            lines.append("注意: 指令列表已按上限截断（数据仍给出完整边界事实）")
        functions = data.get("functions", [])
        if functions:
            lines.append("")
            lines.append("函数（按地址，前 12 个）:")
            for function in functions[:12]:
                lines.append(
                    f"  {function['address']:>10}  {function['size']:>6} 字节  "
                    f"{function['instruction_count']:>5} 条  "
                    f"[{function['source']}] {function['name']}"
                )
        return "\n".join(lines)


def _collect(
    path,
    elf,
    arch: str | None,
    arch_pair: tuple[int, int] | None,
    regions,
    options: dict,
    diagnostics: list[Diagnostic],
) -> tuple[list[dict], list[dict], bool]:
    """Merge symbol bounds with prologue hits and decode instructions."""
    data = path.read_bytes()
    mode = arch_pair[1] if arch_pair else 0

    starts: list[tuple[int, str, int, str]] = []
    known: set[int] = set()
    for name, address, size, table in symbol_functions(elf):
        starts.append((address, name, size, "symbols"))
        known.add(address)

    truncated = False
    if arch is not None:
        for region in regions:
            blob = _region_bytes(data, region)
            if blob is None:
                continue
            region_starts = prologue_starts(
                blob, region.address, arch, 4 if arch == "aarch64" else 1, known
            )
            for address in region_starts:
                starts.append((address, f"sub_{address:x}", 0, "prologue"))
                known.add(address)

    starts.sort(key=lambda item: item[0])
    functions: list[dict] = []
    instructions: list[dict] = []
    budget = options["max_instructions"]
    for index, (address, name, size, source) in enumerate(starts):
        if index + 1 < len(starts):
            extent = starts[index + 1][0] - address
        else:
            extent = _region_end(data, regions, address) - address
        if source == "symbols" and size > 0:
            extent = size
        entry = {
            "name": name,
            "address": hex(address),
            "size": max(extent, 0),
            "source": source,
            "instruction_count": 0,
            "undecoded_bytes": 0,
        }
        if entry["size"] <= 0:
            functions.append(entry)
            continue
        if budget <= 0 or arch_pair is None:
            functions.append(entry)
            continue
        blob = _extent_bytes(data, regions, address, entry["size"])
        if blob is None:
            functions.append(entry)
            continue
        decoded = decode_bytes(blob, address, arch_pair[0], mode)
        if decoded and decoded[0].address > address:
            # The function may start before the first decoded instruction
            # only when the prologue scan misfires; keep the gap visible.
            entry["undecoded_bytes"] = decoded[0].address - address
        covered = sum(item.size for item in decoded)
        entry["instruction_count"] = len(decoded)
        entry["undecoded_bytes"] = max(
            entry["size"] - covered, entry.get("undecoded_bytes", 0)
        )
        for item in decoded:
            if budget <= 0:
                truncated = True
                diagnostics.append(
                    Diagnostic(
                        code="DISASM_TRUNCATED",
                        level=DiagnosticLevel.WARNING,
                        message=(
                            "Instruction list truncated at "
                            f"{options['max_instructions']} entries."
                        ),
                        analyzer_id=ANALYZER_ID,
                    )
                )
                break
            instructions.append(
                {
                    "address": hex(item.address),
                    "size": item.size,
                    "mnemonic": item.mnemonic,
                    "operands": item.op_str,
                    "bytes": item.bytes_hex,
                }
            )
            budget -= 1
        functions.append(entry)
        if len(functions) >= options["max_functions"]:
            truncated = True
            diagnostics.append(
                Diagnostic(
                    code="DISASM_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"Function list truncated at {options['max_functions']} entries."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
            break
    return functions, instructions, truncated


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


def _region_end(data: bytes, regions, address: int) -> int:
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
