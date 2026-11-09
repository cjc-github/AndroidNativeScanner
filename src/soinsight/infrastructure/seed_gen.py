"""Seed corpus generation from recovered format, protocol and constant facts.

A fuzz seed only has to reach the parser, so every seed here is built from a
fact the static analysis actually recovered:

* a **container** seed starts with the magic bytes of a format the image is
  known to carry, so the container parser accepts it on the first try;
* a **protocol** seed is a minimal, well-formed message of a protocol the
  image is known to speak;
* a **constant** seed reproduces a recovered algorithm constant table at the
  offset where it was found, so the code path that consumes the table is
  reached;
* a **generic** seed is a fallback for images with no such facts: plain
  printable bytes, NUL bytes and a deterministic pattern.

The seeds are facts-driven, not guessed magic: each one records the analyzer
its rationale came from, so a reader can tell a targeted seed from a filler.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping

from .constants import signature_words
from .formats import magic_bytes
from .protocol import seed_template

__all__ = ["SeedItem", "build_seeds", "generic_seeds"]

#: Seeds stay small: a corpus of huge inputs only slows the fuzzer down.
DEFAULT_SEED_SIZE = 256
MAX_SEED_SIZE = 4096


@dataclass(frozen=True)
class SeedItem:
    """One generated seed and why it was generated."""

    name: str
    kind: str
    payload: bytes
    rationale: str
    source: str

    @property
    def size(self) -> int:
        return len(self.payload)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
            "rationale": self.rationale,
            "source": self.source,
            "preview": self.payload[:32].hex(),
        }


def _bounded_size(size: int) -> int:
    return max(16, min(int(size), MAX_SEED_SIZE))


def _filler(length: int, seed: int = 0) -> bytes:
    """Deterministic filler that is not a constant run."""
    if length <= 0:
        return b""
    block = bytes((seed + index * 7) % 251 for index in range(256))
    return (block * (length // 256 + 1))[:length]


def _slug(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in str(value)
    ).strip("-").lower() or "seed"


def container_seeds(
    format_facts: Mapping[str, object],
    *,
    size: int = DEFAULT_SEED_SIZE,
) -> list[SeedItem]:
    """Seeds that start with a recognized container format's magic."""
    seeds: list[SeedItem] = []
    entries = format_facts.get("formats") or ()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        format_id = str(entry.get("format") or "")
        if not format_id:
            continue
        magic = magic_bytes(format_id)
        if not magic:
            continue
        payload = (magic + _filler(_bounded_size(size), len(magic)))[:_bounded_size(size)]
        seeds.append(
            SeedItem(
                name=f"container-{_slug(format_id)}",
                kind="container",
                payload=payload,
                rationale=(
                    f"以 {format_id} 的魔数开头，命中图像中已识别的容器格式"
                    f"（偏移 {entry.get('offset', '未知')}）"
                ),
                source="advanced.file-format",
            )
        )
    return seeds


def protocol_seeds(
    protocol_facts: Mapping[str, object],
    *,
    size: int = DEFAULT_SEED_SIZE,
) -> list[SeedItem]:
    """Seeds that are minimal, well-formed messages of a known protocol."""
    seeds: list[SeedItem] = []
    entries = protocol_facts.get("protocols") or ()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        protocol_id = str(entry.get("protocol") or "")
        if not protocol_id:
            continue
        template = seed_template(protocol_id)
        if template is None:
            evidence = entry.get("evidence") or ()
            marker = ""
            for item in evidence:
                if isinstance(item, Mapping) and item.get("source") == "string":
                    marker = str(item.get("detail") or "")
                    break
            if not marker:
                continue
            template = marker.encode("utf-8", "ignore")
        payload = (template + _filler(_bounded_size(size), len(template)))[
            : _bounded_size(size)
        ]
        seeds.append(
            SeedItem(
                name=f"protocol-{_slug(protocol_id)}",
                kind="protocol",
                payload=payload,
                rationale=(
                    f"构造 {protocol_id} 的最小报文，命中图像中已识别的协议特征"
                    f"（证据强度 {entry.get('strength', '未知')}）"
                ),
                source="advanced.protocol",
            )
        )
    return seeds


def constant_seeds(
    constant_facts: Mapping[str, object],
    *,
    size: int = DEFAULT_SEED_SIZE,
) -> list[SeedItem]:
    """Seeds that reproduce a recovered algorithm constant table."""
    seeds: list[SeedItem] = []
    entries = constant_facts.get("hits") or ()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        algorithm = str(entry.get("algorithm") or "")
        if not algorithm:
            continue
        words = signature_words(algorithm)
        if not words:
            continue
        offsets = entry.get("offsets") or ()
        offset_text = str(offsets[0]) if offsets else "0x0"
        try:
            offset = int(offset_text, 0)
        except (TypeError, ValueError):
            offset = 0
        # Keep the constant table at the offset it was recovered from, so the
        # code path that indexes it sees the same layout.
        payload = bytearray(_filler(max(offset, 0) + sum(len(word) for word in words), 0))
        cursor = offset
        for word in words:
            payload[cursor : cursor + len(word)] = word
            cursor += len(word)
        trimmed = bytes(payload)[:_bounded_size(size)]
        seeds.append(
            SeedItem(
                name=f"constant-{_slug(algorithm)}",
                kind="constant",
                payload=trimmed,
                rationale=(
                    f"复现 {algorithm} 的常量表于偏移 {offset_text}，"
                    "命中图像中已识别的算法常量"
                ),
                source="advanced.constants",
            )
        )
    return seeds


def generic_seeds(
    target_bytes: bytes,
    *,
    size: int = DEFAULT_SEED_SIZE,
    minimum: int = 4,
) -> list[SeedItem]:
    """Fallback seeds for an image with no format, protocol or constant facts.

    The corpus is filled to ``minimum`` distinct entries: printable runs,
    NUL padding, deterministic patterns and slices of the target itself.
    Each family contributes more than one seed by varying its base byte, so
    the filler is not a list of identical inputs.
    """
    length = _bounded_size(size)
    digest = hashlib.sha256(target_bytes or b"").digest()
    base = digest[0] or 1

    candidates: list[SeedItem] = []
    for index in range(4):
        candidates.append(
            SeedItem(
                name=f"generic-printable-{index}",
                kind="generic",
                payload=(
                    b"SOInsight seed "
                    + bytes((base + index * 11 + i) % 95 + 32 for i in range(64))
                )
                * (length // 64 + 1),
                rationale="通用种子：可打印字节，缺少可定向的格式/协议/常量事实",
                source="target-bytes",
            )
        )
    for index in range(2):
        candidates.append(
            SeedItem(
                name=f"generic-nul-{index}",
                kind="generic",
                payload=b"\x00" * (length - index * 16),
                rationale="通用种子：NUL 填充，缺少可定向的格式/协议/常量事实",
                source="target-bytes",
            )
        )
    for index in range(4):
        candidates.append(
            SeedItem(
                name=f"generic-pattern-{index}",
                kind="generic",
                payload=_filler(length, base + index * 31),
                rationale="通用种子：确定性字节模式，缺少可定向的格式/协议/常量事实",
                source="target-bytes",
            )
        )
    # A slice of the real target is a legitimate seed too: it is the input the
    # library was actually built against.
    if target_bytes:
        for index in range(2):
            offset = index * length
            candidates.append(
                SeedItem(
                    name=f"generic-target-slice-{index}",
                    kind="generic",
                    payload=target_bytes[offset : offset + length],
                    rationale="通用种子：目标文件自身的字节片段",
                    source="target-bytes",
                )
            )

    wanted = max(1, minimum)
    unique: list[SeedItem] = []
    seen: set[str] = set()
    for seed in candidates:
        digest_value = seed.sha256
        if digest_value in seen:
            continue
        seen.add(digest_value)
        unique.append(seed)
        if len(unique) >= wanted:
            break
    return unique


def build_seeds(
    target_bytes: bytes,
    *,
    format_facts: Mapping[str, object] | None = None,
    protocol_facts: Mapping[str, object] | None = None,
    constant_facts: Mapping[str, object] | None = None,
    min_seeds: int = 8,
    max_seeds: int = 64,
    size: int = DEFAULT_SEED_SIZE,
) -> tuple[list[SeedItem], list[str]]:
    """Build the corpus and report which upstream analyzers contributed.

    Targeted seeds come first; generic seeds only fill the gap up to
    ``min_seeds``. Duplicates are removed by content hash, so two formats with
    the same magic do not produce the same seed twice.
    """
    seeds: list[SeedItem] = []
    sources: list[str] = []

    for facts, builder, source in (
        (format_facts, container_seeds, "advanced.file-format"),
        (protocol_facts, protocol_seeds, "advanced.protocol"),
        (constant_facts, constant_seeds, "advanced.constants"),
    ):
        if not facts:
            continue
        produced = builder(facts, size=size)
        if produced:
            seeds.extend(produced)
            sources.append(source)

    if len(seeds) < max(1, min_seeds):
        produced = generic_seeds(target_bytes, size=size, minimum=max(1, min_seeds) - len(seeds))
        if produced:
            seeds.extend(produced)
            sources.append("target-bytes")

    unique: list[SeedItem] = []
    seen: set[str] = set()
    for seed in seeds:
        digest = seed.sha256
        if digest in seen:
            continue
        seen.add(digest)
        unique.append(seed)

    return unique[: max(1, max_seeds)], sources
