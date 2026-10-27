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
    virtual: bool = False

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
class DwarfMember:
    """One data member of a composite type."""

    name: str
    type_name: str | None = None
    offset: int | None = None
    accessibility: str | None = None
    static: bool = False


@dataclass(frozen=True)
class DwarfBase:
    """One direct base class of a class or struct type."""

    name: str
    offset: int | None = None
    accessibility: str | None = None
    virtual: bool = False


@dataclass(frozen=True)
class DwarfEnumValue:
    """One enumerator of an enumeration type."""

    name: str
    value: int | None = None


@dataclass(frozen=True)
class DwarfType:
    """A composite (class, struct, union or enum) type recovered from DWARF."""

    name: str
    kind: str  # class / struct / union / enum
    byte_size: int | None = None
    members: tuple[DwarfMember, ...] = ()
    bases: tuple[DwarfBase, ...] = ()
    enumerators: tuple[DwarfEnumValue, ...] = ()
    decl_file: str | None = None
    decl_line: int | None = None
    unit_name: str = ""


@dataclass(frozen=True)
class DwarfVariable:
    """A global or static variable described by debug information."""

    name: str
    type_name: str | None = None
    decl_file: str | None = None
    decl_line: int | None = None
    external: bool | None = None
    unit_name: str = ""


@dataclass(frozen=True)
class DwarfInfo:
    """Debug information recovered from one ELF image."""

    functions: tuple[DwarfFunction, ...] = ()
    types: tuple[DwarfType, ...] = ()
    variables: tuple[DwarfVariable, ...] = ()
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

    def types_by_name(self) -> dict[tuple[str, str], DwarfType]:
        """Index composite types by ``(name, kind)``; the first entry wins."""
        index: dict[tuple[str, str], DwarfType] = {}
        for type_ in self.types:
            if type_.name:
                key = (type_.name, type_.kind)
                if key not in index:
                    index[key] = type_
        return index
