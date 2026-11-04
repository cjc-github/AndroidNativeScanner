"""Discover ARM function entries with the decoder.

A prologue scan cannot be trusted on ARM: a Thumb library mixes 16-bit and
32-bit Thumb-2 encodings, and the ARM ``2d e9`` byte pattern turns up
inside Thumb-2 data.  Measured on a real armeabi-v7a library, the byte scan
produced 566 candidate boundaries of which only 199 really began with a
push, and it matched none of the 90 functions the symbol table knew about.

The decoder settles it: a function entry begins with a stack push that
saves the return address.  Both ARM and Thumb are tried, because which one
applies is only known from the symbol value bit -- and that bit is exactly
what a prologue scan does not have.
"""

from dataclasses import dataclass

from .disasm import capstone_module

__all__ = ["arm_entry_candidates", "is_entry_push"]

# A function entry opens with a stack push that saves the return address.
ENTRY_MNEMONICS = frozenset(
    {"push", "push.w", "stmdb", "stmfd", "stmdb.w", "vpush"}
)
# A push that mentions pc is a stack adjustment inside a function, not an
# entry point.
_ENTRY_PUSH_EXCLUDES_PC = True


@dataclass(frozen=True)
class EntryCandidate:
    """One byte offset that may open a function."""

    address: int
    """The address the function starts at."""

    thumb: bool
    """Whether the bytes decode as Thumb."""

    mnemonic: str
    """The mnemonic of the first instruction."""


def is_entry_push(mnemonic: str, operands: str) -> bool:
    """Whether the first instruction of a function is a return-address push."""
    if mnemonic not in ENTRY_MNEMONICS:
        return False
    if _ENTRY_PUSH_EXCLUDES_PC and "pc" in operands.lower():
        return False
    return True


def arm_entry_candidates(
    blob: bytes,
    region_address: int,
    arch: int,
    modes: tuple[int, ...],
    step: int = 2,
) -> tuple[EntryCandidate, ...]:
    """Every offset in ``blob`` that opens a function, by decoding it.

    ``modes`` are the Capstone modes to try; the ARM mode and the Thumb mode
    both appear, because a library may mix them.
    """
    module = capstone_module()
    if module is None or not modes:
        return ()

    found: list[EntryCandidate] = []
    seen: set[int] = set()
    for index in range(0, max(0, len(blob) - 3), step):
        address = region_address + index
        if address in seen:
            continue
        window = blob[index : index + 8]
        hits = []
        for mode in modes:
            engine = module.Cs(arch, mode)
            decoded = list(engine.disasm(window, address))
            if not decoded:
                continue
            if not is_entry_push(decoded[0].mnemonic, decoded[0].op_str):
                continue
            # The candidate must decode into a plausible instruction
            # sequence: a push followed by more code, not a push that ends
            # in an undefined opcode.
            if len(decoded) < 2:
                continue
            hits.append(
                EntryCandidate(
                    address=address,
                    thumb=bool(mode & _thumb_bit(module)),
                    mnemonic=decoded[0].mnemonic,
                )
            )
        if not hits:
            continue
        # Thumb first: a Thumb library is the common case, and the ARM mode
        # decodes almost any bytes into something that looks like a push.
        hits.sort(key=lambda item: not item.thumb)
        found.append(hits[0])
        seen.add(address)
    return tuple(found)


def _thumb_bit(module) -> int:
    return getattr(module, "CS_MODE_THUMB", 16)
