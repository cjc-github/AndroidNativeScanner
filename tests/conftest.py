"""Shared pytest fixtures for SOInsight tests."""

import pytest


@pytest.fixture
def minimal_elf64_little() -> bytes:
    """A 64-byte minimal ELF64 little-endian header (type DYN, x86-64)."""
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = (
        (3).to_bytes(2, "little")
        + (62).to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (0x401000).to_bytes(8, "little")
        + (64).to_bytes(8, "little")
        + (1024).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (64).to_bytes(2, "little")
        + (56).to_bytes(2, "little")
        + (8).to_bytes(2, "little")
        + (64).to_bytes(2, "little")
        + (12).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
    )
    return ident + header
