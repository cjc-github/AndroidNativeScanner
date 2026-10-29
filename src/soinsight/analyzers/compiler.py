"""``advanced.compiler``: identify the compiler and toolchain of the image."""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.compiler import identify
from ..infrastructure.elf import ElfFormatError, parse_elf
from ..infrastructure.strings import extract_strings

ANALYZER_ID = "advanced.compiler"

_DEFAULT_OPTIONS = {
    "max_scan_bytes": 33554432,
    "max_symbols": 5000,
    "max_strings": 2000,
    "min_length": 4,
}

_FAMILY_LABELS = {
    "c": "C 工具链",
    "c++": "C++ 工具链",
    "rust": "Rust",
    "swift": "Swift",
    "ndk": "Android NDK",
    "wasm": "WebAssembly",
}

_STRENGTH_LABELS = {"single": "单一证据", "corroborated": "多源印证"}


class AdvancedCompilerAnalyzer(Analyzer):
    """Identify the compiler and toolchain that built the image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Compiler Analyzer",
        version="1.0.0",
        description="Identify the compiler and toolchain of the image.",
        requires=(),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        blob, truncated = _read_head(target.real_path, options["max_scan_bytes"])
        if truncated:
            diagnostics.append(
                Diagnostic(
                    code="COMPILER_INPUT_TRUNCATED",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"The file exceeds the {options['max_scan_bytes']} byte "
                        "scan cap; the tail was not scanned."
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        elf = _optional_elf(target.real_path)
        comment_text = _section_text(target.real_path, elf, ".comment")
        if not comment_text:
            # A non-ELF blob (or an ELF whose .comment was stripped) still
            # carries toolchain banners inside its printable strings.
            comment_text = " ".join(_string_values(blob, options))
        note_text = (
            _section_text(target.real_path, elf, ".note.gnu.build-id")
            or _section_text(target.real_path, elf, ".note.android.ident")
        )
        symbol_names = _symbol_names(elf, options["max_symbols"])
        hits = identify(comment_text, note_text, symbol_names)

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "scanned_bytes": len(blob),
                "file_size": target.size,
                "scan_truncated": truncated,
                "symbol_count": len(symbol_names),
                "comment_sections": _comment_section_names(elf),
                "has_build_id": bool(elf and any(
                    section.name.startswith(".note.gnu.build-id")
                    for section in elf.sections
                )),
                "has_android_ident": bool(elf and any(
                    section.name.startswith(".note.android.ident")
                    for section in elf.sections
                )),
                "toolchain_count": len(hits),
                "corroborated_count": sum(
                    1 for item in hits if item.strength == "corroborated"
                ),
                "toolchains": [
                    {
                        "toolchain": item.toolchain,
                        "family": item.family,
                        "version": item.version,
                        "strength": item.strength,
                        "evidence": [
                            {"source": ev.source, "detail": ev.detail}
                            for ev in item.evidence
                        ],
                    }
                    for item in hits
                ],
                "families": _family_counts(hits),
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format toolchain facts as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== 编译器识别 ===",
            f"识别: {data.get('toolchain_count', 0)} 个工具链"
            f"（多源印证 {data.get('corroborated_count', 0)} 个）",
        ]
        if data.get("has_build_id"):
            lines.append("Build ID: 存在")
        if data.get("has_android_ident"):
            lines.append("Android 标识 note: 存在")
        if data.get("scan_truncated"):
            lines.append("注意: 输入已按上限截断，尾部未扫描")
        toolchains = data.get("toolchains", [])
        if toolchains:
            lines.append("")
            lines.append("识别结果:")
            for item in toolchains:
                family = _FAMILY_LABELS.get(item["family"], item["family"])
                strength = _STRENGTH_LABELS.get(item["strength"], item["strength"])
                version = f" 版本 {item['version']}" if item.get("version") else ""
                lines.append(
                    f"  {item['toolchain']:<16} [{family}]{version} {strength}"
                )
                for evidence in item["evidence"][:4]:
                    lines.append(f"      - {evidence['detail']}")
        else:
            lines.append("未识别出已知编译工具链")
        return "\n".join(lines)


def _family_counts(hits) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in hits:
        counts[item.family] = counts.get(item.family, 0) + 1
    return counts


def _section_text(path, elf, prefix: str) -> str:
    """Printable text of the first section whose name starts with ``prefix``."""
    if elf is None:
        return ""
    for section in elf.sections:
        if section.name.startswith(prefix) and section.size > 0:
            blob = _read_section(path, section.offset, section.size)
            extraction = extract_strings(blob, min_length=1)
            return " ".join(entry.value for entry in extraction.entries)
    return ""


def _read_section(path, offset: int, size: int) -> bytes:
    with open(path, "rb") as stream:
        stream.seek(offset)
        return stream.read(size)


def _comment_section_names(elf) -> tuple[str, ...]:
    if elf is None:
        return ()
    return tuple(
        section.name
        for section in elf.sections
        if section.name.startswith(".comment")
    )


def _string_values(blob: bytes, options: dict) -> tuple[str, ...]:
    extraction = extract_strings(blob, min_length=options["min_length"])
    return tuple(entry.value for entry in extraction.entries[: options["max_strings"]])


def _symbol_names(elf, limit: int) -> tuple[str, ...]:
    if elf is None:
        return ()
    names: list[str] = []
    seen: set[str] = set()
    for symbol in elf.symbols:
        if not symbol.name or symbol.name in seen:
            continue
        seen.add(symbol.name)
        names.append(symbol.name)
        if len(names) >= limit:
            break
    return tuple(names)


def _read_head(path, limit: int) -> tuple[bytes, bool]:
    with open(path, "rb") as stream:
        blob = stream.read(limit)
    try:
        size = path.stat().st_size
    except OSError:
        size = len(blob)
    return blob, size > len(blob)


def _optional_elf(path):
    try:
        return parse_elf(path)
    except (ElfFormatError, OSError):
        return None


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("max_scan_bytes", "max_symbols", "max_strings", "min_length"):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(1, value)
    return resolved
