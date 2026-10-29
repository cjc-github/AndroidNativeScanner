"""Third-party library identification from link-level evidence.

The module combines four cheap, link-level signals into library judgements:
``DT_NEEDED`` entries and the ``SONAME`` (the loader-time names), the names of
defined/imported symbols (an ``EVP_*`` export is a strong OpenSSL signal), and
version strings found in the image (``OpenSSL 1.1.1``, ``zlib 1.2.11``).

Every library is identified independently, each match carries the evidence it
was based on, and the ``strength`` field distinguishes single-source matches
from corroborated ones -- stronger, but never a verdict. The module stays
signature-driven: a library is reported only when a concrete fingerprint hit.
"""

from dataclasses import dataclass

__all__ = ["LibraryEvidence", "LibraryHit", "LibraryReport", "identify"]


@dataclass(frozen=True)
class LibraryEvidence:
    """One fingerprint that matched a library."""

    source: str
    """Where the evidence came from (``needed``, ``soname``, ``symbol``,
    ``string``)."""

    detail: str
    """The concrete fingerprint, for the report and the text renderer."""


@dataclass(frozen=True)
class LibraryHit:
    """A library identification, with every fingerprint that matched."""

    library: str
    """Stable library identifier (``zlib``, ``libc++``, ...)."""

    family: str
    """Grouping: ``runtime``, ``crypto``, ``compression``, ``image``,
    ``network``, ``serialization``, ``xml``, ``media``, ``logging``."""

    strength: str
    """``single`` when one source matched, ``corroborated`` for two or more."""

    evidence: tuple[LibraryEvidence, ...]
    """The fingerprints that hit."""


@dataclass(frozen=True)
class LibraryReport:
    """The libraries identified in the image."""

    libraries: tuple[LibraryHit, ...]

    @property
    def corroborated_count(self) -> int:
        return sum(1 for item in self.libraries if item.strength == "corroborated")


def identify(
    needed: tuple[str, ...],
    soname: str | None,
    symbol_names: tuple[str, ...],
    string_values: tuple[str, ...],
) -> LibraryReport:
    """Match link-level evidence against the library fingerprint table."""
    hits: list[LibraryHit] = []
    string_pool = frozenset(string_values)
    needed_pool = frozenset(needed)
    if soname:
        needed_pool = needed_pool | {soname}

    for fingerprint in _LIBRARIES:
        evidence: list[LibraryEvidence] = []
        for needed_name in fingerprint.get("needed", ()):
            if needed_name in needed_pool:
                evidence.append(
                    LibraryEvidence("needed", needed_name)
                )
        for symbol in fingerprint.get("symbols", ()):
            if any(name.startswith(symbol) for name in symbol_names):
                evidence.append(LibraryEvidence("symbol", symbol))
        for version in fingerprint.get("strings", ()):
            if any(version in value for value in string_values):
                evidence.append(LibraryEvidence("string", version))
        if not evidence:
            continue
        strength = "corroborated" if len(evidence) >= 2 else "single"
        hits.append(
            LibraryHit(
                library=fingerprint["library"],
                family=fingerprint["family"],
                strength=strength,
                evidence=tuple(evidence),
            )
        )

    hits.sort(key=lambda item: (-len(item.evidence), item.library))
    return LibraryReport(libraries=tuple(hits))


_LIBRARIES: tuple[dict, ...] = (
    # Runtime and C++ support libraries.
    {
        "library": "libc++",
        "family": "runtime",
        "needed": ("libc++.so", "libc++_shared.so", "libc++abi.so"),
        "symbols": ("_ZSt",),
        "strings": ("libc++",),
    },
    {
        "library": "libstdc++",
        "family": "runtime",
        "needed": ("libstdc++.so",),
        "symbols": ("_ZSt",),
        "strings": ("libstdc++",),
    },
    {
        "library": "gnustl",
        "family": "runtime",
        "needed": ("libgnustl_shared.so",),
        "symbols": ("_ZN6__gnu_cxx",),
    },
    {
        "library": "Android logging",
        "family": "logging",
        "needed": ("liblog.so",),
        "symbols": ("__android_log_print",),
    },
    # Cryptographic libraries.
    {
        "library": "OpenSSL",
        "family": "crypto",
        "needed": ("libcrypto.so", "libssl.so"),
        "symbols": ("EVP_aes_256_gcm", "BIO_new", "SSL_CTX_new", "RSA_new"),
        "strings": ("OpenSSL ", "openssl-"),
    },
    {
        "library": "BoringSSL",
        "family": "crypto",
        "needed": ("libboringssl.so",),
        "symbols": ("EVP_aes_256_gcm", "SSL_CTX_new"),
        "strings": ("BoringSSL", "boringssl"),
    },
    {
        "library": "mbedTLS",
        "family": "crypto",
        "needed": ("libmbedtls.so",),
        "symbols": ("mbedtls_ssl_init", "mbedtls_cipher_setup"),
        "strings": ("mbed TLS", "mbedtls-"),
    },
    {
        "library": "libsodium",
        "family": "crypto",
        "needed": ("libsodium.so",),
        "symbols": ("crypto_secretbox_easy", "sodium_init"),
        "strings": ("libsodium",),
    },
    # Compression and archives.
    {
        "library": "zlib",
        "family": "compression",
        "needed": ("libz.so",),
        "symbols": ("inflate", "deflate", "inflateInit2_", "deflateInit2_"),
        "strings": ("zlib 1.",),
    },
    {
        "library": "liblzma",
        "family": "compression",
        "needed": ("liblzma.so",),
        "symbols": ("lzma_stream_decoder", "lzma_easy_encoder"),
        "strings": ("liblzma", "XZ Utils"),
    },
    {
        "library": "bzip2",
        "family": "compression",
        "needed": ("libbz2.so",),
        "symbols": ("BZ2_bzDecompress", "BZ2_bzCompress"),
        "strings": ("bzip2",),
    },
    # Images.
    {
        "library": "libpng",
        "family": "image",
        "needed": ("libpng.so",),
        "symbols": ("png_create_read_struct", "png_set_read_fn"),
        "strings": ("libpng",),
    },
    {
        "library": "libjpeg",
        "family": "image",
        "needed": ("libjpeg.so", "libjpeg-turbo.so"),
        "symbols": ("jpeg_CreateDecompress", "jpeg_read_header"),
        "strings": ("libjpeg", "libjpeg-turbo"),
    },
    {
        "library": "libwebp",
        "family": "image",
        "needed": ("libwebp.so",),
        "symbols": ("WebPDecode", "WebPEncode"),
        "strings": ("libwebp",),
    },
    # Networking and protocol libraries.
    {
        "library": "libcurl",
        "family": "network",
        "needed": ("libcurl.so",),
        "symbols": ("curl_easy_init", "curl_easy_perform"),
        "strings": ("libcurl",),
    },
    {
        "library": "c-ares",
        "family": "network",
        "needed": ("libcares.so",),
        "symbols": ("ares_init", "ares_gethostbyname"),
        "strings": ("c-ares",),
    },
    # Serialization and data formats.
    {
        "library": "protobuf",
        "family": "serialization",
        "needed": ("libprotobuf.so",),
        "symbols": ("_ZN6google8protobuf",),
        "strings": ("protobuf",),
    },
    {
        "library": "json-c",
        "family": "serialization",
        "needed": ("libjson-c.so",),
        "symbols": ("json_object_new_object", "json_object_get_string"),
        "strings": ("json-c",),
    },
    {
        "library": "SQLite",
        "family": "serialization",
        "needed": ("libsqlite.so",),
        "symbols": ("sqlite3_open", "sqlite3_prepare_v2"),
        "strings": ("SQLite version",),
    },
    # XML.
    {
        "library": "libxml2",
        "family": "xml",
        "needed": ("libxml2.so",),
        "symbols": ("xmlParseFile", "xmlReadMemory"),
        "strings": ("libxml",),
    },
    {
        "library": "expat",
        "family": "xml",
        "needed": ("libexpat.so",),
        "symbols": ("XML_ParserCreate", "XML_Parse"),
        "strings": ("expat",),
    },
    # Media and rendering.
    {
        "library": "FFmpeg",
        "family": "media",
        "needed": ("libavcodec.so", "libavformat.so", "libavutil.so"),
        "symbols": ("avcodec_open2", "avformat_open_input"),
        "strings": ("FFmpeg", "libavcodec", "libavformat"),
    },
    {
        "library": "freetype",
        "family": "image",
        "needed": ("libfreetype.so",),
        "symbols": ("FT_New_Face", "FT_Load_Char"),
        "strings": ("FreeType", "freetype"),
    },
)
