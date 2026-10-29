"""Algorithm identification from constant, symbol and string evidence.

An algorithm is reported when the evidence for it is consistent, and the
evidence kind is recorded with it. Three independent sources are combined:

* a constant table from ``advanced.constants``;
* an imported or exported symbol whose name belongs to a known library or
  names the primitive itself;
* a string that names the primitive or the library that implements it.

A source on its own is reported at ``single`` strength; two or more sources
agreeing raise it to ``corroborated``. Nothing is inferred from absence: a
binary with no crypto evidence simply reports no algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import ConstantHit

# Symbol-name fragments that name a cryptographic library or primitive. The
# fragment is matched against demangled and raw symbol names.
_SYMBOL_MARKERS: tuple[tuple[str, str, str], ...] = (
    # (marker, name, family)
    ("EVP_", "OpenSSL", "library"),
    ("SHA256_", "SHA-256", "hash"),
    ("SHA1_", "SHA-1", "hash"),
    ("SHA512_", "SHA-512", "hash"),
    ("MD5_", "MD5", "hash"),
    ("AES_", "AES", "cipher"),
    ("RSA_", "RSA", "cipher"),
    ("BIO_", "OpenSSL", "library"),
    ("CRYPTO_", "OpenSSL", "library"),
    ("BoringSSL", "BoringSSL", "library"),
    ("CCCryptor", "CommonCrypto", "library"),
    ("SecKey", "Security framework", "library"),
    ("bcrypt", "bcrypt", "hash"),
    ("argon2", "Argon2", "hash"),
    ("scrypt", "scrypt", "hash"),
    ("pbkdf2", "PBKDF2", "kdf"),
    ("hkdf", "HKDF", "kdf"),
    ("zlib", "zlib", "compression"),
    ("deflate", "deflate", "compression"),
    ("inflate", "inflate", "compression"),
    ("lz4", "LZ4", "compression"),
    ("zstd", "zstd", "compression"),
    ("base64", "Base64", "encoding"),
)

# Strings that name a library or primitive outright.
_STRING_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("OpenSSL", "OpenSSL", "library"),
    ("BoringSSL", "BoringSSL", "library"),
    ("libcrypto", "OpenSSL", "library"),
    ("libssl", "OpenSSL", "library"),
    ("CommonCrypto", "CommonCrypto", "library"),
    ("libsodium", "libsodium", "library"),
    ("mbedtls", "mbed TLS", "library"),
    ("wolfSSL", "wolfSSL", "library"),
    ("GnuTLS", "GnuTLS", "library"),
    ("zlib", "zlib", "compression"),
    ("liblz4", "LZ4", "compression"),
    ("libzstd", "zstd", "compression"),
    ("AES", "AES", "cipher"),
    ("ChaCha20", "ChaCha20", "cipher"),
    ("SHA-256", "SHA-256", "hash"),
    ("SHA256", "SHA-256", "hash"),
    ("MD5", "MD5", "hash"),
    ("RSA", "RSA", "cipher"),
    ("Base64", "Base64", "encoding"),
)

# How a constant-table hit maps onto an algorithm judgement.
_CONSTANT_ALGORITHMS: dict[str, tuple[str, str]] = {
    "AES": ("AES", "cipher"),
    "AES inverse S-box": ("AES", "cipher"),
    "ChaCha20": ("ChaCha20", "cipher"),
    "RC4": ("RC4", "cipher"),
    "MD5": ("MD5", "hash"),
    "SHA-256": ("SHA-256", "hash"),
    "SHA-1": ("SHA-1", "hash"),
    "CRC32": ("CRC32", "checksum"),
    "zlib deflate": ("zlib deflate", "compression"),
    "Base64": ("Base64", "encoding"),
}


@dataclass(frozen=True)
class AlgorithmEvidence:
    """One algorithm with the sources that support it."""

    algorithm: str
    family: str
    strength: str  # single | corroborated
    sources: tuple[str, ...]  # constants | symbols | strings
    evidence: tuple[str, ...]  # the concrete names/offsets that matched


@dataclass(frozen=True)
class AlgorithmReport:
    """Every algorithm judgement for one image."""

    algorithms: tuple[AlgorithmEvidence, ...]

    @property
    def corroborated_count(self) -> int:
        return sum(
            1 for item in self.algorithms if item.strength == "corroborated"
        )


def identify(
    constant_hits: tuple[ConstantHit, ...],
    symbol_names: tuple[str, ...],
    string_values: tuple[str, ...],
) -> AlgorithmReport:
    """Cross-check the three evidence sources into algorithm judgements."""
    supports: dict[str, set[str]] = {}
    families: dict[str, str] = {}
    evidence: dict[str, set[str]] = {}

    def record(algorithm: str, family: str, source: str, detail: str) -> None:
        key = algorithm
        supports.setdefault(key, set()).add(source)
        families[key] = family
        evidence.setdefault(key, set()).add(detail)

    for hit in constant_hits:
        mapped = _CONSTANT_ALGORITHMS.get(hit.algorithm)
        if mapped is None:
            continue
        algorithm, family = mapped
        offsets = ", ".join(hex(offset) for offset in hit.offsets[:4])
        record(algorithm, family, "constants", f"{hit.algorithm} @ {offsets}")

    for name in symbol_names:
        # A name can carry several markers, so every match is recorded.
        for marker, algorithm, family in _SYMBOL_MARKERS:
            if marker in name:
                record(algorithm, family, "symbols", name)

    for value in string_values:
        for marker, algorithm, family in _STRING_MARKERS:
            if marker in value:
                record(algorithm, family, "strings", value)

    algorithms = tuple(
        AlgorithmEvidence(
            algorithm=algorithm,
            family=families[algorithm],
            strength="corroborated" if len(sources) > 1 else "single",
            sources=tuple(sorted(sources)),
            evidence=tuple(sorted(details)[:8]),
        )
        for algorithm, sources in sorted(supports.items())
        for details in [evidence[algorithm]]
    )
    return AlgorithmReport(algorithms)


def families() -> tuple[str, ...]:
    """Distinct algorithm families the cross-check can report."""
    seen: list[str] = []
    for _marker, _algorithm, family in _SYMBOL_MARKERS + _STRING_MARKERS:
        if family not in seen:
            seen.append(family)
    for _algorithm, family in _CONSTANT_ALGORITHMS.values():
        if family not in seen:
            seen.append(family)
    return tuple(seen)
