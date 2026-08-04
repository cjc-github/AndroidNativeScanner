"""Scan profile model."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    id: str
    name: str
    analyzer_ids: tuple[str, ...]
    description: str = ""
