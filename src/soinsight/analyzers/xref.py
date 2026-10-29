"""``basic.xref``: cross-references between code and data.

The analyzer links instructions to the string literals they point at. It
combines the code regions recovered by ``basic.disasm`` with the printable
strings found in the allocated (loaded) sections of the image, and reports
every instruction whose operand resolves to a string address.

The result is a fact set: it reports where a string is used, never a finding.
Judgment about the meaning of a reference lives in the ``security.*`` rules.
"""

from bisect import bisect_right
from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.disasm import capstone_version, decode_architecture
from ..infrastructure.elf import ElfFormatError, parse_elf
from ..infrastructure.strings import extract_strings
from ..infrastructure.xref import decode_references

ANALYZER_ID = "basic.xref"

_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4
_SHT_NOBITS = 0x8

# Reference kinds that denote a control transfer instead of a data access.
_CONTROL_FLOW_KINDS = frozenset({"branch"})

_DEFAULT_OPTIONS = {
    "min_length": 4,
    "max_strings": 20000,
    "max_xrefs": 5000,
}


class BasicXrefAnalyzer(Analyzer):
    """Resolve code references to the string literals of the image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Cross-Reference Analyzer",
        version="1.0.0",
        description=(
            "Resolve instruction operands to the string literals they point at."
        ),
        requires=("basic.disasm",),
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
        if arch_pair is None:
            diagnostics.append(
                Diagnostic(
                    code="XREF_UNSUPPORTED_ARCH",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"No decoder for machine {elf.header.machine}; "
                        "cross-references are not resolved."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )
        decoder_version = capstone_version()
        if decoder_version is None:
            diagnostics.append(
                Diagnostic(
                    code="XREF_DECODER_UNAVAILABLE",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        "Capstone is not installed; cross-references are not "
                        "resolved (pip install capstone)."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        disasm_result = context.require("basic.disasm")
        disasm_data = disasm_result.data or {}
        regions = disasm_data.get("code_regions", [])
        if not regions:
            diagnostics.append(
                Diagnostic(
                    code="XREF_NO_CODE_REGIONS",
                    level=DiagnosticLevel.WARNING,
                    message="No executable section with an address is present.",
                    analyzer_id=ANALYZER_ID,
                )
            )

        with open(target.real_path, "rb") as stream:
            strings, strings_truncated = _collect_strings(elf, stream, options)
        if strings_truncated:
            diagnostics.append(
                Diagnostic(
                    code="XREF_STRINGS_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The string table was truncated to "
                        f"{options['max_strings']} entries."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        table = _StringTable(strings)

        xrefs: list[dict] = []
        referenced: set[str] = set()
        truncated = False
        if arch_pair is not None and decoder_version is not None:
            with open(target.real_path, "rb") as stream:
                xrefs, truncated = _resolve_references(
                    stream,
                    regions,
                    disasm_data.get("functions", []),
                    arch_pair,
                    table,
                    options,
                )
            referenced = {entry["string_address"] for entry in xrefs}
            if truncated:
                diagnostics.append(
                    Diagnostic(
                        code="XREF_TRUNCATED",
                        level=DiagnosticLevel.WARNING,
                        message=(
                            f"The cross-reference list was truncated to "
                            f"{options['max_xrefs']} entries."
                        ),
                        analyzer_id=ANALYZER_ID,
                    )
                )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "arch": disasm_data.get("arch"),
                "decoder": decoder_version,
                "code_region_count": len(regions),
                "string_count": len(strings),
                "strings_truncated": strings_truncated,
                "referenced_string_count": len(referenced),
                "xref_count": len(xrefs),
                "truncated": truncated,
                "xrefs": xrefs,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format cross-reference facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 交叉引用 ===",
            f"架构: {data.get('arch') or 'N/A'}"
            f"（解码器: {data.get('decoder') or '不可用'}）",
            f"代码区域: {data.get('code_region_count', 0)} 个",
            f"字符串总数: {data.get('string_count', 0)}",
            f"被引用字符串数: {data.get('referenced_string_count', 0)}",
            f"交叉引用数: {data.get('xref_count', 0)}",
        ]
        if data.get("truncated"):
            lines.append("（结果已截断）")
        xrefs = data.get("xrefs", [])
        if xrefs:
            lines.append("")
            lines.append("=== 引用样本 ===")
            for entry in xrefs[:10]:
                value = entry.get("string", "")
                if len(value) > 60:
                    value = value[:57] + "..."
                lines.append(
                    f"  {entry.get('instruction_address')} -> "
                    f"{entry.get('string_address')} "
                    f"[{entry.get('kind')}] {value}"
                )
            if len(xrefs) > 10:
                lines.append(f"  ... 以及另外 {len(xrefs) - 10} 条")
        return "\n".join(lines)


class _StringTable:
    """Address to string lookup with suffix containment support."""

    def __init__(self, strings: list[dict]) -> None:
        self._entries = sorted(strings, key=lambda item: item["address"])
        self._addresses = [item["address"] for item in self._entries]

    def lookup(self, target: int) -> tuple[dict, str] | None:
        """Return the string at ``target`` and the match kind."""
        index = bisect_right(self._addresses, target) - 1
        if index < 0:
            return None
        entry = self._entries[index]
        if entry["address"] == target:
            return entry, "exact"
        if target < entry["address"] + len(entry["value"]):
            return entry, "suffix"
        return None


class _Region:
    """One executable section mapped between virtual and file addresses."""

    def __init__(self, name: str, address: int, offset: int, size: int) -> None:
        self.name = name
        self.address = address
        self.offset = offset
        self.size = size

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.size

    def file_offset(self, address: int) -> int:
        return self.offset + (address - self.address)


def _collect_strings(elf, stream, options: dict) -> tuple[list[dict], bool]:
    """Extract printable strings from the loaded sections of the image."""
    strings: list[dict] = []
    truncated = False
    for section in elf.sections:
        if not section.flags & _SHF_ALLOC or section.size <= 0:
            continue
        if section.flags & _SHF_EXECINSTR:
            # Code sections carry unwind tables and jump tables whose bytes
            # look like strings; they are not string literals.
            continue
        if section.type_value == _SHT_NOBITS or section.address <= 0:
            continue
        blob = _section_bytes(stream, section)
        if not blob:
            continue
        extraction = extract_strings(
            blob, min_length=options["min_length"]
        )
        for entry in extraction.entries:
            if len(strings) >= options["max_strings"]:
                truncated = True
                break
            strings.append(
                {
                    "value": entry.value,
                    "offset": section.offset + entry.offset,
                    "address": section.address + entry.offset,
                    "section": section.name,
                }
            )
        if truncated:
            break
    return strings, truncated


def _section_bytes(stream, section) -> bytes:
    """Read the file bytes backing ``section``."""
    stream.seek(section.offset)
    return stream.read(section.size)


def _resolve_references(
    stream,
    regions: list[dict],
    functions: list[dict],
    arch_pair: tuple[int, int],
    table: _StringTable,
    options: dict,
) -> tuple[list[dict], bool]:
    """Decode the code of every function and match its operands to strings.

    Functions are decoded one by one instead of scanning whole sections:
    compilers embed literal pools inside the text section, and decoding them
    as instructions desynchronises the linear decode of everything that
    follows. Code that belongs to no function is decoded afterwards so that
    PLT stubs and similar regions are covered too.
    """
    arch, mode = arch_pair
    xrefs: list[dict] = []
    truncated = False

    mapped = _mapped_regions(regions)
    if not mapped:
        return xrefs, truncated

    # A symbol size can overshoot the section that hosts it, so every extent is
    # clipped to its own region: reading past its end would decode the bytes of
    # whatever follows in the file as instructions.
    extents: list[tuple[_Region, int, int, str | None]] = []
    for function in functions:
        extent = _function_extent(function)
        if extent is None:
            continue
        start, end, name = extent
        region = _region_of(mapped, start)
        if region is None:
            continue
        end = min(end, region.address + region.size)
        if end <= start:
            continue
        extents.append((region, start, end, name))

    for region, start, end, name in extents:
        if truncated:
            break
        blob = _read(stream, region.file_offset(start), end - start)
        if not blob:
            continue
        xrefs, truncated = _collect(
            blob, start, arch, mode, table, name, xrefs, options, truncated
        )
    if not truncated:
        for region in mapped:
            xrefs, truncated = _collect_gaps(
                stream, region, extents, arch, mode, table, xrefs, options
            )
            if truncated:
                break
    return xrefs, truncated


def _mapped_regions(regions: list[dict]) -> list[_Region]:
    """Turn the reported code regions into address mappers."""
    mapped: list[_Region] = []
    for region in regions:
        try:
            address = int(region.get("address", "0"), 16)
            offset = int(region.get("offset", "0"), 16)
        except (TypeError, ValueError):
            continue
        size = int(region.get("size", 0) or 0)
        if size <= 0:
            continue
        mapped.append(_Region(region.get("name", ""), address, offset, size))
    return mapped


def _function_extent(function: dict) -> tuple[int, int, str | None] | None:
    """Return ``(start, end, name)`` of a reported function."""
    try:
        start = int(function.get("address", "0"), 16)
    except (TypeError, ValueError):
        return None
    size = int(function.get("size", 0) or 0)
    if size <= 0:
        return None
    return start, start + size, function.get("name")


def _region_of(regions: list[_Region], address: int) -> _Region | None:
    """Return the region that contains ``address``."""
    for region in regions:
        if region.contains(address):
            return region
    return None


def _read(stream, offset: int, size: int) -> bytes:
    """Read ``size`` bytes at ``offset``; returns fewer bytes near EOF."""
    if offset < 0 or size <= 0:
        return b""
    stream.seek(offset)
    return stream.read(size)


def _collect(
    blob: bytes,
    start_address: int,
    arch: int,
    mode: int,
    table: _StringTable,
    function: str | None,
    xrefs: list[dict],
    options: dict,
    truncated: bool,
) -> tuple[list[dict], bool]:
    """Decode one blob and append the references that hit a string."""
    for reference in decode_references(blob, start_address, arch, mode):
        if truncated:
            break
        if reference.kind in _CONTROL_FLOW_KINDS:
            # A branch target is code; it can never be a string literal.
            continue
        hit = table.lookup(reference.target)
        if hit is None:
            continue
        entry, match_kind = hit
        if len(xrefs) >= options["max_xrefs"]:
            truncated = True
            break
        xrefs.append(
            {
                "string": entry["value"],
                "string_address": hex(entry["address"]),
                "string_offset": hex(entry["offset"]),
                "section": entry["section"],
                "instruction_address": hex(reference.address),
                "function": function,
                "kind": reference.kind,
                "match": match_kind,
            }
        )
    return xrefs, truncated


def _collect_gaps(
    stream,
    region: _Region,
    extents: list[tuple[_Region, int, int, str | None]],
    arch: int,
    mode: int,
    table: _StringTable,
    xrefs: list[dict],
    options: dict,
) -> tuple[list[dict], bool]:
    """Decode the parts of a region that belong to no known function."""
    truncated = False
    covered = sorted(
        (start, end) for candidate, start, end, _ in extents if candidate is region
    )
    cursor = region.address
    for start, end in covered:
        if start > cursor:
            blob = _read(stream, region.file_offset(cursor), start - cursor)
            if blob:
                xrefs, truncated = _collect(
                    blob, cursor, arch, mode, table, None, xrefs, options, truncated
                )
                if truncated:
                    return xrefs, truncated
        cursor = max(cursor, end)
    if cursor < region.address + region.size:
        blob = _read(
            stream,
            region.file_offset(cursor),
            region.address + region.size - cursor,
        )
        if blob:
            xrefs, truncated = _collect(
                blob, cursor, arch, mode, table, None, xrefs, options, truncated
            )
    return xrefs, truncated


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and ranges enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("min_length", "max_strings", "max_xrefs"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    return resolved
