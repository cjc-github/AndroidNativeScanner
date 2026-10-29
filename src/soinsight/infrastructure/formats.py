"""Embedded and outer file-format detection.

The module scans a raw blob for the magic signatures of common container,
archive, image, audio, document, mobile and executable formats, both at offset 0
(the outer format of the target itself) and anywhere else (resources, assets and
payloads embedded in a larger file such as a native library). Every hit reports
its byte offset so the analyzer can attribute it to a section when the target is
an ELF image.

A hit is ``verified`` when a cheap structural check beyond the magic holds (for
example a JPEG that also contains the EOI marker, or a ZIP whose central
directory magic appears near the end of the buffer). ``verified`` is evidence
strength, never a verdict: the analyzer reports facts and leaves judgement to
the security rules.
"""

from dataclasses import dataclass
from typing import Callable

__all__ = ["FormatHit", "scan"]

_MAX_OFFSETS_PER_FORMAT = 64


@dataclass(frozen=True)
class FormatHit:
    """One occurrence of an embedded or outer format signature."""

    format: str
    """Stable format identifier (``zip``, ``png``, ``dex``, ...)."""

    category: str
    """Grouping: ``archive``, ``image``, ``audio``, ``document``, ``mobile``,
    ``executable``, ``data``."""

    magic: str
    """Signature bytes as hex, for evidence display."""

    offset: int
    """Byte offset of the signature in the scanned blob."""

    verified: bool
    """Whether a structural check beyond the magic passed."""

    def as_dict(self) -> dict:
        return {
            "format": self.format,
            "category": self.category,
            "magic": self.magic,
            "offset": hex(self.offset),
            "verified": self.verified,
        }


def _verify_zip(blob: bytes, offset: int) -> bool:
    """A ZIP is trusted when an EOCD record follows the local header."""
    return b"PK\x05\x06" in blob[offset + 22 : offset + 65557]


def _verify_png(blob: bytes, offset: int) -> bool:
    return blob[offset + 8 : offset + 12] == b"IHDR"


def _verify_jpeg(blob: bytes, offset: int) -> bool:
    return b"\xff\xd9" in blob[offset : offset + 65536]


def _verify_dex(blob: bytes, offset: int) -> bool:
    # ``dex\n`` + three decimal digits + NUL.
    return len(blob) >= offset + 8 and blob[offset + 4 : offset + 7].isdigit()


def _verify_elf(blob: bytes, offset: int) -> bool:
    return len(blob) >= offset + 6 and blob[offset + 4] in (1, 2)


def _verify_gif(blob: bytes, offset: int) -> bool:
    return blob[offset + 6 : offset + 10] in (b"87a", b"89a")


def _verify_bzip2(blob: bytes, offset: int) -> bool:
    return len(blob) >= offset + 4 and blob[offset + 3] in b"123456789"


def _verify_macho(blob: bytes, offset: int) -> bool:
    # The first big-endian word is the architecture count; a sane image has
    # between one and a handful of slots.
    if len(blob) < offset + 8:
        return False
    count = int.from_bytes(blob[offset + 4 : offset + 8], "big")
    return 1 <= count <= 64


def _verify_fat_macho(blob: bytes, offset: int) -> bool:
    # ``cafebabe`` heads both a fat Mach-O and a Java class file; the words that
    # follow disambiguate: fat files carry a small big-endian arch count, class
    # files a minor/major version pair. Both are reported, but only the form
    # whose structure is plausible is marked verified.
    if len(blob) < offset + 8:
        return False
    count = int.from_bytes(blob[offset + 4 : offset + 8], "big")
    return 1 <= count <= 64


def _verify_java_class(blob: bytes, offset: int) -> bool:
    if len(blob) < offset + 8:
        return False
    version = blob[offset + 6 : offset + 8]
    return version in (b"\x00\x2d", b"\x00\x2e", b"\x00\x2f", b"\x00\x30",
                       b"\x00\x31", b"\x00\x32", b"\x00\x33", b"\x00\x34",
                       b"\x00\x35", b"\x00\x36", b"\x00\x37", b"\x00\x38",
                       b"\x00\x39", b"\x00\x3a", b"\x00\x3b", b"\x00\x3c",
                       b"\x00\x3d", b"\x00\x3e", b"\x00\x3f", b"\x00\x40",
                       b"\x00\x41", b"\x00\x42", b"\x00\x43", b"\x00\x44",
                       b"\x00\x45", b"\x00\x46", b"\x00\x47", b"\x00\x48",
                       b"\x00\x49", b"\x00\x4a", b"\x00\x4b", b"\x00\x4c")


def _verify_riff(blob: bytes, offset: int) -> bool:
    return blob[offset + 8 : offset + 12] in (b"WAVE", b"AVI ", b"WEBP", b"RMID")


_SIGNATURES: tuple[tuple[str, str, bytes, Callable[[bytes, int], bool]], ...] = (
    ("zip", "archive", b"PK\x03\x04", _verify_zip),
    ("png", "image", b"\x89PNG\r\n\x1a\n", _verify_png),
    ("jpeg", "image", b"\xff\xd8\xff", _verify_jpeg),
    ("gif", "image", b"GIF8", _verify_gif),
    ("pdf", "document", b"%PDF-", lambda blob, offset: True),
    ("dex", "mobile", b"dex\n", _verify_dex),
    ("apk-signing-block", "mobile", b"APK Sig Block 42", lambda blob, offset: True),
    ("elf", "executable", b"\x7fELF", _verify_elf),
    ("macho", "executable", b"\xfe\xed\xfa\xce", _verify_macho),
    ("macho64", "executable", b"\xfe\xed\xfa\xcf", _verify_macho),
    ("fat-macho", "executable", b"\xca\xfe\xba\xbe", _verify_fat_macho),
    ("java-class", "executable", b"\xca\xfe\xba\xbe", _verify_java_class),
    ("wasm", "executable", b"\x00asm", lambda blob, offset: True),
    ("gzip", "archive", b"\x1f\x8b\x08", lambda blob, offset: True),
    ("bzip2", "archive", b"BZh", _verify_bzip2),
    ("xz", "archive", b"\xfd7zXZ\x00", lambda blob, offset: True),
    ("7z", "archive", b"7z\xbc\xaf\x27\x1c", lambda blob, offset: True),
    ("sqlite", "data", b"SQLite format 3\x00", lambda blob, offset: True),
    ("riff", "audio", b"RIFF", _verify_riff),
    ("ogg", "audio", b"OggS", lambda blob, offset: True),
)


def scan(blob: bytes, *, max_hits: int = 200) -> tuple[FormatHit, ...]:
    """Locate format signatures in ``blob``, longer signatures first."""
    hits: list[FormatHit] = []
    # ``cafebabe`` matches both fat Mach-O and Java class files; both are
    # reported as separate facts and each carries its own verification.
    for format_id, category, signature, verify in _SIGNATURES:
        start = 0
        while len(hits) < max_hits:
            found = blob.find(signature, start)
            if found < 0:
                break
            hits.append(
                FormatHit(
                    format=format_id,
                    category=category,
                    magic=signature.hex(),
                    offset=found,
                    verified=verify(blob, found),
                )
            )
            start = found + 1
    return tuple(sorted(hits, key=lambda hit: (hit.offset, hit.format)))
