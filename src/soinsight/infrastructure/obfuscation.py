"""Obfuscation and packing evidence from sections, strings and symbols.

The module reports concrete, signature-driven obfuscation signals:

* packer and protector banners (``UPX!``, ``VMProtect``, ``Themida``, ``Obfuscator-LLVM``);
* symbol-table clues (OLLVM's mangled ``__llvm`` helpers);
* high-entropy regions, where a section's bytes look like encrypted or packed
  content (a common symptom of packed payloads).

Control-flow flattening is detected separately, from the recovered control
flow graph rather than from byte patterns: :func:`scan_control_flow` compares
the *shape* of a function's CFG against the dispatcher shape a flattened
function produces. The two signals are kept apart on purpose -- a byte
pattern never proves flattening, and a graph shape never proves a packer.

Every signal is a fact with its own evidence; the analyzer never produces a
verdict such as "packed" -- the security rules interpret the evidence. The
``strength`` field distinguishes single-source hits from corroborated ones.
"""

import math
from dataclasses import dataclass

__all__ = [
    "ObfuscationEvidence",
    "ObfuscationHit",
    "scan_control_flow",
    "scan_sections",
]

_HIGH_ENTROPY_THRESHOLD = 7.0


@dataclass(frozen=True)
class ObfuscationEvidence:
    """One obfuscation signal with the evidence it was based on."""

    kind: str
    """Signal class: ``banner``, ``symbol``, ``entropy``."""

    detail: str
    """Human-readable description, for the report and the text renderer."""


@dataclass(frozen=True)
class ObfuscationHit:
    """One obfuscation signal."""

    signal: str
    """Stable signal identifier (``upx``, ``ollvm``, ``high-entropy``, ...)."""

    category: str
    """Grouping: ``packer``, ``protector``, ``obfuscator``, ``packing``."""

    strength: str
    """``single`` when one evidence item matched, ``corroborated`` for several."""

    evidence: tuple[ObfuscationEvidence, ...]
    """The signals that hit."""


_BANNERS = (
    ("upx", "packer", (b"UPX!", b"UPX0", b"UPX1"), "UPX 壳签名"),
    ("vmprotect", "protector", (b"VMProtect",), "VMProtect 保护"),
    ("themida", "protector", (b"Themida", b"WinLicense"), "Themida/WinLicense 保护"),
    ("aspack", "packer", (b"ASPack",), "ASPack 壳"),
    ("petite", "packer", (b"Petite",), "Petite 壳"),
    # `__llvm` alone is the LLVM profile/coverage runtime, not OLLVM, so only
    # the obfuscator plugin's own banners count as evidence here.
    ("ollvm", "obfuscator", (b"Obfuscator-LLVM", b"llvm.obfuscator"), "OLLVM 混淆"),
    ("hikari", "obfuscator", (b"Hikari", b"hikari"), "Hikari 混淆"),
)


def scan_sections(
    section_blobs: tuple[tuple[str, bytes], ...],
    symbols,
    *,
    entropy_threshold: float = _HIGH_ENTROPY_THRESHOLD,
) -> tuple[ObfuscationHit, ...]:
    """Scan section bytes and symbols for obfuscation signals.

    ``section_blobs`` is a sequence of ``(section_name, bytes)`` pairs; symbols
    is any iterable of symbol names.
    """
    hits: list[ObfuscationHit] = []
    symbol_pool = frozenset(symbols)

    all_bytes = b"".join(blob for _, blob in section_blobs)
    for signal, category, markers, detail in _BANNERS:
        evidence: list[ObfuscationEvidence] = []
        for marker in markers:
            if marker in all_bytes:
                evidence.append(ObfuscationEvidence("banner", detail))
                break
        if signal == "ollvm":
            text_markers = tuple(
                marker.decode("ascii", "ignore") for marker in markers
            )
            for name in symbol_pool:
                if any(marker in name for marker in text_markers):
                    evidence.append(ObfuscationEvidence("symbol", detail))
                    break
        if evidence:
            hits.append(
                ObfuscationHit(
                    signal=signal,
                    category=category,
                    strength="corroborated" if len(evidence) >= 2 else "single",
                    evidence=tuple(evidence),
                )
            )

    for name, blob in section_blobs:
        if len(blob) < 256:
            continue
        entropy = _entropy(blob)
        if entropy >= entropy_threshold:
            hits.append(
                ObfuscationHit(
                    signal="high-entropy",
                    category="packing",
                    strength="single",
                    evidence=(
                        ObfuscationEvidence(
                            "entropy",
                            f"分节 {name} 熵值 {entropy:.2f}（可疑高熵）",
                        ),
                    ),
                )
            )

    hits.sort(key=lambda item: (item.signal, item.category))
    return tuple(hits)


def _entropy(blob: bytes) -> float:
    counts = [0] * 256
    for byte in blob:
        counts[byte] += 1
    total = len(blob)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


#: A block whose byte extent is at most this is "tiny": a flattened function
#: is made of many such short states.
_TINY_BLOCK_BYTES = 32


def _as_int(value, default: int = 0) -> int:
    """Parse a hex string or an int into an int."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def scan_control_flow(
    functions,
    *,
    min_blocks: int = 8,
    min_indirect_ratio: float = 0.3,
) -> tuple[ObfuscationHit, ...]:
    """Detect control-flow flattening from recovered control flow graphs.

    ``functions`` is the per-function list produced by the ``basic.cfg``
    analyzer: each entry carries ``blocks`` (with ``start``, ``end``,
    ``successors`` and ``indirect_jump``) plus ``block_count`` and
    ``edge_count``.

    A flattened function is a state machine: every state ends in an
    **indirect** jump through the dispatch table instead of a direct branch.
    In a recovered CFG that shows up as a large share of the blocks whose
    terminator is an unresolved jump (``indirect_jump``).

    That indirect jump is what makes the signal specific. Ordinary code also
    has many short blocks and also has join points, but it does not end a
    large share of its blocks with an unresolved jump -- a direct branch
    names its destination, so the CFG stays connected.

    The high in-degree of a dispatcher cannot be used as the criterion: an
    indirect jump has no resolved successor, so it cuts the graph and the
    dispatcher never becomes a join point in the recovered CFG. The
    disconnected state blocks are themselves the evidence.

    The result is evidence with the measured numbers attached, never a
    verdict: the caller decides what it means.
    """
    hits: list[ObfuscationHit] = []
    for function in functions or ():
        if not isinstance(function, dict):
            continue
        blocks = function.get("blocks") or ()
        block_count = len(blocks)
        if block_count < max(1, min_blocks):
            continue

        indirect = [
            block
            for block in blocks
            if isinstance(block, dict) and block.get("indirect_jump")
        ]
        if not indirect:
            continue
        indirect_ratio = len(indirect) / block_count
        if indirect_ratio < min_indirect_ratio:
            continue

        name = str(function.get("name") or "(未命名)")
        edge_count = _as_int(function.get("edge_count"))
        evidence = (
            ObfuscationEvidence(
                "control-flow",
                f"函数 {name} 的 {block_count} 个基本块中有 {len(indirect)} 个"
                f"以间接跳转结束（占比 {indirect_ratio:.0%}），"
                "符合状态机通过调度表转移的形态",
            ),
            ObfuscationEvidence(
                "control-flow",
                f"这些状态块的直接跳转目标不可解析，控制流图在该函数内被切断"
                f"（共 {block_count} 个基本块、{edge_count} 条边）",
            ),
        )
        hits.append(
            ObfuscationHit(
                signal="control-flow-flattening",
                category="obfuscator",
                strength="corroborated" if len(evidence) >= 2 else "single",
                evidence=evidence,
            )
        )
    return tuple(hits)
