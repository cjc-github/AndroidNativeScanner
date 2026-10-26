"""Printable string extraction over raw bytes.

Extraction dedupes by value and keeps the byte offset of the first
occurrence plus the occurrence count, so an analyzer can report
"unique strings with locations" instead of raw tool output.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ExtractedString:
    """One unique printable string and where it first appears."""

    value: str
    offset: int
    occurrences: int = 1


@dataclass(frozen=True)
class Extraction:
    """The extraction result: unique entries plus occurrence bookkeeping.

    ``entries`` is truncated to ``max_entries`` while ``occurrence_count`` and
    ``unique_count`` always describe the whole input, so the caller can notice
    truncation without losing the totals.
    """

    entries: tuple[ExtractedString, ...]
    occurrence_count: int
    unique_count: int
    scanned_bytes: int

    @property
    def truncated(self) -> bool:
        return self.unique_count > len(self.entries)


def extract_strings(
    data: bytes,
    *,
    min_length: int = 4,
    max_entries: int | None = None,
) -> Extraction:
    """Extract printable ASCII runs of at least ``min_length`` bytes from data."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_length))
    first_offset: dict[str, int] = {}
    occurrence_counts: dict[str, int] = {}
    order: list[str] = []
    occurrence_count = 0
    for match in pattern.finditer(data):
        occurrence_count += 1
        value = match.group().decode("ascii")
        counts = occurrence_counts.get(value)
        if counts is None:
            first_offset[value] = match.start()
            occurrence_counts[value] = 1
            order.append(value)
        else:
            occurrence_counts[value] = counts + 1

    if max_entries is None:
        kept = tuple(
            ExtractedString(value, first_offset[value], occurrence_counts[value])
            for value in order
        )
    else:
        kept = tuple(
            ExtractedString(value, first_offset[value], occurrence_counts[value])
            for value in order[: max(0, max_entries)]
        )
    return Extraction(
        entries=kept,
        occurrence_count=occurrence_count,
        unique_count=len(order),
        scanned_bytes=len(data),
    )
