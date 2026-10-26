"""Pure-Python printable string extraction.

This package replaces the external ``strings`` tool used by V1: the extraction
works on raw bytes (any file, not only ELF) and keeps the byte offset of every
string so downstream analyzers can attach evidence locations.
"""

from .classify import Classification, SENSITIVE_PATTERNS, classify_string
from .extractor import ExtractedString, Extraction, extract_strings

__all__ = [
    "Classification",
    "ExtractedString",
    "Extraction",
    "SENSITIVE_PATTERNS",
    "classify_string",
    "extract_strings",
]
