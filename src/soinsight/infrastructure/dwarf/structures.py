"""Immutable value objects produced by the DWARF parser."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DwarfParameter:
    """One formal parameter of a debug-info function."""

    name: str
    type_name: str | None = None


@dataclass(frozen=True)
class DwarfFunction:
    """A function described by debug information.

    ``linkage_name`` is the mangled symbol name when the compiler emitted one;
    it is the key used to join a function to the dynamic symbol table. ``name``
    is the source-level name and may be empty for compiler-generated code.
    """

    name: str
    linkage_name: str = ""
    low_pc: int | None = None
    high_pc: int | None = None
    return_type: str | None = None
    decl_file: str | None = None
    decl_line: int | None = None
    parameters: tuple[DwarfParameter, ...] = ()
    unit_name: str = ""

    @property
    def signature(self) -> str:
        """Best-effort source-level signature, e.g. ``int add(int a, int b)``."""
        rendered = ", ".join(
            f"{parameter.type_name} {parameter.name}".strip()
            if parameter.type_name
            else parameter.name
            for parameter in self.parameters
        )
        head = self.name or self.linkage_name or "<unnamed>"
        body = f"{head}({rendered})"
        return f"{self.return_type} {body}" if self.return_type else body


@dataclass(frozen=True)
class DwarfInfo:
    """Debug information recovered from one ELF image."""

    functions: tuple[DwarfFunction, ...] = ()
    units: tuple[str, ...] = ()
    version: int | None = None
    has_debug_info: bool = False

    def by_linkage_name(self) -> dict[str, DwarfFunction]:
        """Index functions by mangled name; the first entry wins."""
        index: dict[str, DwarfFunction] = {}
        for function in self.functions:
            if function.linkage_name and function.linkage_name not in index:
                index[function.linkage_name] = function
        return index
