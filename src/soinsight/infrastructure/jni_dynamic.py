"""JNI dynamic registration recovery from data-section evidence.

A library that registers natives dynamically calls ``RegisterNatives`` from
``JNI_OnLoad`` with a ``JNINativeMethod`` array: ``{const char *name,
const char *signature, void *fnPtr}``. The array lives in a writable allocated
section (usually ``.data.rel.ro``) and, in a position-independent image, every
entry pointer carries a load-time relocation -- which the loader needs to work,
so strip does not remove it. That is the anchor this module uses:

1. the image must export ``JNI_OnLoad`` and import ``RegisterNatives``;
2. every relocation ``R_*_RELATIVE`` on a data section slot is a candidate
   pointer; consecutive slots are grouped as ``JNINativeMethod`` entries when
   the first points at a printable method name, the second at a Java method
   descriptor and the third into executable memory;
3. the function pointer is resolved back to a symbol when either symbol table
   still names it, and stays a bare address otherwise.

The method *name* is what ``RegisterNatives`` received: either a bare method
name (the common case -- the class comes from ``FindClass`` at run time and is
not recoverable statically) or a fully-qualified one. Which of the two it is, is
reported as a fact, never guessed.

Instruction-level validation (proving the array is referenced from inside
``JNI_OnLoad``) needs the disassembly layer; without it the shape match stands
on its own and the result says so.
"""

from dataclasses import dataclass

__all__ = [
    "JniDynamicRegistration",
    "JniDynamicReport",
    "find_dynamic_registrations",
]

_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4

_MIN_NAME_LENGTH = 1
_MAX_NAME_LENGTH = 128
_MAX_SIGNATURE_LENGTH = 256


@dataclass(frozen=True)
class JniDynamicRegistration:
    """One method the image registers at load time."""

    method_name: str
    """The ``name`` string handed to ``RegisterNatives``."""

    qualified: bool
    """Whether ``method_name`` is fully qualified (``com.foo.Bar.method``)."""

    signature: str
    """The ``signature`` string, a Java method descriptor."""

    function_address: int
    """Virtual address of the registered native function."""

    function_symbol: str | None
    """Symbol-table name of the function, ``None`` when it is stripped."""

    array_slot: int
    """Virtual address of the ``JNINativeMethod`` entry the facts came from."""

    relocation_offsets: tuple[str, ...]
    """The three relocation slots, as hex strings, for the evidence chain."""

    def as_dict(self) -> dict:
        return {
            "method_name": self.method_name,
            "qualified": self.qualified,
            "signature": self.signature,
            "function_address": hex(self.function_address),
            "function_symbol": self.function_symbol,
            "function_named": self.function_symbol is not None,
            "array_slot": hex(self.array_slot),
            "relocation_offsets": list(self.relocation_offsets),
        }


@dataclass(frozen=True)
class JniDynamicReport:
    """The dynamic-registration facts of one image."""

    on_load_present: bool
    register_natives_imported: bool
    registrations: tuple[JniDynamicRegistration, ...]
    array_count: int
    unnamed_function_count: int
    blocked_reason: str | None = None
    """Why nothing could be reported, when both flags above are false."""


def find_dynamic_registrations(elf, blob: bytes) -> JniDynamicReport:
    """Locate the ``JNINativeMethod`` arrays of an ELF image."""
    from .elf import parse_relocations

    on_load = _find_on_load(elf)
    imported = _imports_register_natives(elf)

    if on_load is None and not imported:
        return JniDynamicReport(
            on_load_present=False,
            register_natives_imported=False,
            registrations=(),
            array_count=0,
            unnamed_function_count=0,
            blocked_reason=(
                "既没有导出 JNI_OnLoad 也没有导入 RegisterNatives："
                "该镜像不做动态 JNI 注册。"
            ),
        )

    is64 = elf.header.elf_class == "ELF64"
    pointer_size = 8 if is64 else 4
    prefix = "<" if elf.header.endianness == "little" else ">"
    relocations = parse_relocations(
        blob,
        prefix=prefix,
        is64=is64,
        sections=elf.sections,
        dynsym=tuple(s for s in elf.symbols if s.table == ".dynsym"),
    )
    targets = _relocation_targets(relocations, pointer_size)

    exec_ranges = tuple(
        (section.address, section.address + section.size)
        for section in elf.sections
        if section.flags & _SHF_EXECINSTR and section.size > 0
    )
    symbols_by_address = {
        symbol.value: symbol.name
        for symbol in elf.symbols
        if symbol.is_defined and symbol.is_function and symbol.value > 0 and symbol.name
    }

    registrations: list[JniDynamicRegistration] = []
    array_count = 0
    seen_slots: set[int] = set()

    for section in elf.sections:
        if not (section.flags & _SHF_ALLOC) or section.flags & _SHF_EXECINSTR:
            continue
        if section.type_value == 8:  # SHT_NOBITS: nothing to read
            continue
        if section.size < 3 * pointer_size or section.address == 0:
            continue
        offset = 0
        while offset + 3 * pointer_size <= section.size:
            slot = section.address + offset
            if slot in seen_slots:
                offset += 3 * pointer_size
                continue
            entry = _match_entry(
                blob, elf, slot, section, offset, pointer_size, targets, exec_ranges
            )
            if entry is None:
                offset += pointer_size
                continue
            # Collect the whole consecutive run of well-formed entries.
            run_length = 0
            while entry is not None:
                registrations.append(entry)
                seen_slots.add(section.address + offset)
                run_length += 1
                offset += 3 * pointer_size
                if offset + 3 * pointer_size > section.size:
                    break
                entry = _match_entry(
                    blob,
                    elf,
                    section.address + offset,
                    section,
                    offset,
                    pointer_size,
                    targets,
                    exec_ranges,
                )
            if run_length:
                array_count += 1

    registrations.sort(key=lambda item: item.function_address)
    unnamed = sum(1 for item in registrations if item.function_symbol is None)
    return JniDynamicReport(
        on_load_present=on_load is not None,
        register_natives_imported=imported,
        registrations=tuple(registrations),
        array_count=array_count,
        unnamed_function_count=unnamed,
        blocked_reason=None,
    )


def _find_on_load(elf):
    """The exported ``JNI_OnLoad`` function, version-suffixed or plain."""
    for symbol in elf.symbols:
        if not symbol.is_defined or not symbol.is_function or symbol.value <= 0:
            continue
        name = symbol.name or ""
        if name == "JNI_OnLoad" or name.startswith("JNI_OnLoad@"):
            return symbol
    return None


def _imports_register_natives(elf) -> bool:
    return any(
        (symbol.name or "") == "RegisterNatives"
        for symbol in elf.symbols
        if not symbol.is_defined
    )


def _relocation_targets(relocations, pointer_size: int) -> dict[int, int]:
    """Map each relocated slot to the virtual address it will hold."""
    targets: dict[int, int] = {}
    for relocation in relocations:
        if relocation.kind == "rela" and relocation.symbol_name is None:
            # A RELATIVE addend is the absolute address the slot ends up with.
            targets[relocation.offset] = relocation.addend
        elif relocation.kind == "rel" and relocation.symbol_name is None:
            # REL entries keep the value inline; addend is unused (always 0).
            targets[relocation.offset] = relocation.addend
    return targets


def _string_at(blob: bytes, elf, address: int, limit: int) -> str | None:
    """Read the NUL-terminated string at a virtual address, if printable."""
    file_offset = _vaddr_to_offset(elf, address)
    if file_offset is None:
        return None
    end = blob.find(b"\x00", file_offset, file_offset + limit + 1)
    if end < 0 or end == file_offset:
        return None
    raw = blob[file_offset:end]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isprintable() or "\n" in text or "\t" in text:
        return None
    return text


def _vaddr_to_offset(elf, address: int) -> int | None:
    for section in elf.sections:
        if (
            section.flags & _SHF_ALLOC
            and section.size > 0
            and section.address <= address < section.address + section.size
        ):
            return section.offset + (address - section.address)
    return None


def _is_executable(address: int, exec_ranges) -> bool:
    return any(start <= address < end for start, end in exec_ranges)


def _is_method_name(text: str) -> bool:
    """A plausible ``RegisterNatives`` name: bare or fully qualified."""
    if not (_MIN_NAME_LENGTH <= len(text) <= _MAX_NAME_LENGTH):
        return False
    parts = text.split(".")
    return all(part and (part[0].isalpha() or part[0] == "_") for part in parts)


def _is_descriptor(text: str) -> bool:
    """A plausible Java method descriptor: ``(...)RET``."""
    if not text.startswith("(") or ")" not in text:
        return False
    if not (_MIN_NAME_LENGTH <= len(text) <= _MAX_SIGNATURE_LENGTH):
        return False
    closing = text.rindex(")")
    return_type = text[closing + 1 :]
    if not return_type:
        return False
    return return_type[0] in "VZBCSIJFDL["


def _match_entry(
    blob: bytes,
    elf,
    slot: int,
    section,
    offset_in_section: int,
    pointer_size: int,
    targets: dict[int, int],
    exec_ranges,
) -> JniDynamicRegistration | None:
    """Return one registration when the three slots look like an entry."""
    name_addr = targets.get(slot)
    sig_addr = targets.get(slot + pointer_size)
    fn_addr = targets.get(slot + 2 * pointer_size)
    if name_addr is None or sig_addr is None or fn_addr is None:
        return None

    name = _string_at(blob, elf, name_addr, _MAX_NAME_LENGTH)
    signature = _string_at(blob, elf, sig_addr, _MAX_SIGNATURE_LENGTH)
    if name is None or not _is_method_name(name):
        return None
    if signature is None or not _is_descriptor(signature):
        return None
    if not _is_executable(fn_addr, exec_ranges):
        return None

    qualified = "." in name
    symbol = _symbol_for(elf, fn_addr)
    return JniDynamicRegistration(
        method_name=name,
        qualified=qualified,
        signature=signature,
        function_address=fn_addr,
        function_symbol=symbol,
        array_slot=slot,
        relocation_offsets=(
            hex(slot),
            hex(slot + pointer_size),
            hex(slot + 2 * pointer_size),
        ),
    )


def _symbol_for(elf, address: int) -> str | None:
    """Name of the function at ``address``, preferring the regular table."""
    candidates = [
        symbol
        for symbol in elf.symbols
        if symbol.is_defined
        and symbol.is_function
        and symbol.value == address
        and symbol.name
    ]
    if not candidates:
        return None
    regular = [symbol for symbol in candidates if symbol.table == ".symtab"]
    chosen = regular[0] if regular else candidates[0]
    return chosen.name
