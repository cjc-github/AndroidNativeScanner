"""Obfuscation and packing evidence from sections, strings and symbols.

The module reports concrete, signature-driven obfuscation signals:

* packer and protector banners (``UPX!``, ``VMProtect``, ``Themida``, ``Obfuscator-LLVM``);
* symbol-table clues (OLLVM's mangled ``__llvm`` helpers);
* high-entropy regions, where a section's bytes look like encrypted or packed
  content (a common symptom of packed payloads).

Control-flow flattening detection is deliberately out of scope here: deciding
that a graph is flattened needs the recovered CFG and a shape comparison, so it
is left to a later capability rather than guessed from byte patterns.

Every signal is a fact with its own evidence; the analyzer never produces a
verdict such as "packed" -- the security rules interpret the evidence. The
``strength`` field distinguishes single-source hits from corroborated ones.
"""

import math
from dataclasses import dataclass

__all__ = ["ObfuscationEvidence", "ObfuscationHit", "scan_sections"]

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
