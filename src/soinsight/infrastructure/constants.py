"""Signature constant tables for algorithm identification.

Each entry names an algorithm and carries the constant words its reference
implementation uses. A match is reported only when every word appears in the
scanned data, which keeps a partial overlap from being reported as a hit:
the facts name the algorithm and where its constants were found, and the
judgement about what that means stays with ``advanced.algorithm``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConstantSignature:
    """One algorithm's constant words, in the order they appear in code."""

    algorithm: str
    family: str  # cipher | hash | compression | encoding | checksum
    words: tuple[bytes, ...]


# Signatures are the published constant words of the reference
# implementations. Words are byte sequences, so a table compiled for either
# endianness matches its own layout.
SIGNATURES: tuple[ConstantSignature, ...] = (
    # AES S-box and its inverse, plus the round constants.
    ConstantSignature(
        "AES",
        "cipher",
        (
            bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
            bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
        ),
    ),
    ConstantSignature(
        "AES inverse S-box",
        "cipher",
        (bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),),
    ),
    # MD5 T-table first words and SHA-256 initial hash values.
    ConstantSignature(
        "MD5",
        "hash",
        (bytes.fromhex("d76aa478e8c7b756"),),
    ),
    ConstantSignature(
        "SHA-256",
        "hash",
        (bytes.fromhex("67e6096a85ae67bb"),),
    ),
    ConstantSignature(
        "SHA-1",
        "hash",
        (bytes.fromhex("0123456789abcdeffedcba9876543210f0e1d2c3"),),
    ),
    # CRC32 polynomial in reflected and normal form.
    ConstantSignature(
        "CRC32",
        "checksum",
        (bytes.fromhex("edb88320"),),
    ),
    # zlib/deflate length and distance base tables.
    ConstantSignature(
        "zlib deflate",
        "compression",
        (bytes.fromhex("00010101010101010202020202020203"),),
    ),
    # Base64 alphabet as emitted by the standard encoder.
    ConstantSignature(
        "Base64",
        "encoding",
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",),
    ),
    # ChaCha20/Salsa20 sigma constant.
    ConstantSignature(
        "ChaCha20",
        "cipher",
        (b"expand 32-byte k",),
    ),
    # RC4 is keyed, but the identity permutation initialisation is a common
    # tell for a table-driven implementation.
    ConstantSignature(
        "RC4",
        "cipher",
        (bytes(range(16)),),
    ),
)


@dataclass(frozen=True)
class ConstantHit:
    """One algorithm whose signature was found, with the match locations.

    ``offsets`` are file offsets of the signature's first word; ``sections``
    is left empty for the caller to fill from the ELF section table.
    """

    algorithm: str
    family: str
    offsets: tuple[int, ...]
    sections: tuple[str, ...] = ()


def scan(
    data: bytes,
    signatures: tuple[ConstantSignature, ...] = SIGNATURES,
    *,
    max_hits_per_algorithm: int = 8,
) -> tuple[ConstantHit, ...]:
    """Report every signature whose words all appear in ``data``.

    A signature matches only when all of its words are present, so a single
    coincidental word never produces a hit. Locations are reported for the
    first word of the signature, capped at ``max_hits_per_algorithm``.
    """
    if not data:
        return ()
    hits: list[ConstantHit] = []
    for signature in signatures:
        offsets: list[int] = []
        for word in signature.words:
            if not word or word not in data:
                offsets = []
                break
            if not offsets:
                offsets = _all_offsets(data, word, max_hits_per_algorithm)
        if offsets:
            hits.append(
                ConstantHit(
                    algorithm=signature.algorithm,
                    family=signature.family,
                    offsets=tuple(offsets),
                    sections=(),
                )
            )
    return tuple(hits)


def _all_offsets(data: bytes, word: bytes, limit: int) -> list[int]:
    """Offsets of every occurrence of ``word``, capped at ``limit``."""
    offsets: list[int] = []
    position = data.find(word)
    while position != -1 and len(offsets) < limit:
        offsets.append(position)
        position = data.find(word, position + 1)
    return offsets


def families() -> tuple[str, ...]:
    """Distinct families covered by the signature table."""
    seen: list[str] = []
    for signature in SIGNATURES:
        if signature.family not in seen:
            seen.append(signature.family)
    return tuple(seen)
