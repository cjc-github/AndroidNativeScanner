"""String classification into URL, sensitive and encoded-payload facts.

The pattern tables are migrated from V1 (``src/analyzer/url_analyzer.py``,
``sensitive_analyzer.py`` and ``base64_analyzer.py``) so results stay
comparable across versions. Classification is intentionally a fact
extraction: it never judges severity or risk, which is the job of the
built-in ``security.*`` rules.
"""

import base64
import re
from dataclasses import dataclass

_URL_RE = re.compile(r"https?://[^\s\"']+")

# V1 parity: exact keys, exact expressions. "Password/Token" deliberately
# keeps its loose shape so V1/V2 scans agree on what it reports.
SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "OpenAI Key": r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "JWT": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Password/Token": r"(?:pass(?:word)?|pwd|token|auth)[\"'=:\\s]+[^\"\\s]+",
}

_SENSITIVE_COMPILED = {key: re.compile(expr) for key, expr in SENSITIVE_PATTERNS.items()}

_BASE64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
_BASE64_MAX_BYTES = 4096
_PRINTABLE_RATIO = 0.6
_DECODED_PREVIEW_CHARS = 120


@dataclass(frozen=True)
class Classification:
    """One classified fact: a category, the supporting value and its label."""

    category: str
    label: str
    value: str
    decoded: str | None = None


def classify_string(value: str) -> tuple[Classification, ...]:
    """Return every classification that applies to ``value``.

    A URL embedded in a credential-bearing line yields both facts. Strings
    longer than ``_BASE64_MAX_BYTES`` are skipped: a URL or credential is
    never that long, and skipping bounds the classification cost.
    """
    if len(value) > _BASE64_MAX_BYTES:
        return ()
    matched: list[Classification] = []
    url = _URL_RE.search(value)
    if url:
        matched.append(Classification("url", "url", url.group(0)))
    for label, pattern in _SENSITIVE_COMPILED.items():
        if pattern.search(value):
            matched.append(Classification("sensitive", label, value))
    if _BASE64_CANDIDATE.match(value):
        decoded = _decodable_preview(value)
        if decoded is not None:
            matched.append(Classification("base64", "base64", value, decoded))
    return tuple(matched)


def _decodable_preview(candidate: str) -> str | None:
    try:
        decoded_bytes = base64.b64decode(candidate, validate=True)
        decoded = decoded_bytes.decode("utf-8", errors="strict")
    except Exception:
        return None
    printable = sum(1 for char in decoded if char.isprintable()) / max(1, len(decoded))
    if printable <= _PRINTABLE_RATIO:
        return None
    return decoded[:_DECODED_PREVIEW_CHARS]
