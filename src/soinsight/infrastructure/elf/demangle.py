"""Itanium C++ ABI symbol demangler.

Android NDK builds export C++ symbols under the Itanium ABI mangling scheme
(``_Z...``). Without a demangler an exported-function list is unreadable and,
more importantly, the parameter types are invisible: the mangled name is the
only place where ``ns::Class::method(int const&)`` survives a strip.

This is a self-contained recursive-descent implementation of the ABI subset
that covers real-world ELF exports: nested and local names, templates with
substitutions, builtin and compound types, operators, constructors and
destructors, and the compiler-generated special names (vtables, typeinfo,
guard variables, thunks).

Substitution handling follows the reference mangler (GCC ``cp/mangle.cc``):

* ``St Sa Sb Ss Si So Sd`` are standard abbreviations and are never numbered;
* ``S_`` is candidate 0, ``S0_`` is candidate 1, ``S1_`` is candidate 2, ...;
* candidates are registered, in order of appearance, for template prefixes
  (before their arguments), for complete names, and for every non-builtin type.

Anything outside that subset is returned undecoded rather than guessed: a wrong
signature is worse than a mangled one. The public entry point never raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class _DemangleError(Exception):
    """Internal: the mangled name is outside the supported subset."""


KIND_FUNCTION = "function"
KIND_METHOD = "method"
KIND_CONSTRUCTOR = "constructor"
KIND_DESTRUCTOR = "destructor"
KIND_OPERATOR = "operator"
KIND_DATA = "data"
KIND_SPECIAL = "special"
KIND_UNMANGLED = "unmangled"
KIND_UNDECODED = "undecoded"


@dataclass(frozen=True)
class DemangledSymbol:
    """A decoded C++ symbol.

    ``parameters`` holds demangled parameter types; it is empty for data
    symbols and for functions whose mangling carries no parameter list.
    ``return_type`` is only set when the ABI encodes it (function templates
    and conversion operators).
    """

    display: str
    kind: str
    qualified_name: str = ""
    namespace: str = ""
    short_name: str = ""
    parameters: tuple[str, ...] = ()
    return_type: str | None = None
    language: str = "c++"


_BUILTIN_TYPES = {
    "v": "void",
    "w": "wchar_t",
    "b": "bool",
    "c": "char",
    "a": "signed char",
    "h": "unsigned char",
    "s": "short",
    "t": "unsigned short",
    "i": "int",
    "j": "unsigned int",
    "l": "long",
    "m": "unsigned long",
    "x": "long long",
    "y": "unsigned long long",
    "n": "__int128",
    "o": "unsigned __int128",
    "f": "float",
    "d": "double",
    "e": "long double",
    "g": "__float128",
    "z": "...",
}

_BUILTIN_TYPES_LONG = {
    "Dn": "decltype(nullptr)",
    "Di": "char32_t",
    "Ds": "char16_t",
    "Du": "char8_t",
    "Da": "auto",
    "Dc": "decltype(auto)",
    # Half-precision floating point. "Dh" is the spelling the NDK's libc++
    # emits; "DF" is the Itanium ABI code. Both name the same type.
    "Dh": "half",
    "DF": "half",
}

# Standard abbreviations. Never numbered, never substitution candidates.
_STANDARD_SUBSTITUTIONS = {
    "t": "std",
    "a": "std::allocator",
    "b": "std::basic_string",
    "s": "std::string",
    "i": "std::istream",
    "o": "std::ostream",
    "d": "std::iostream",
}

_OPERATORS = {
    "nw": "new",
    "na": "new[]",
    "dl": "delete",
    "da": "delete[]",
    "ps": "+",
    "ng": "-",
    "ad": "&",
    "de": "*",
    "co": "~",
    "pl": "+",
    "mi": "-",
    "ml": "*",
    "dv": "/",
    "rm": "%",
    "an": "&",
    "or": "|",
    "eo": "^",
    "aS": "=",
    "pL": "+=",
    "mI": "-=",
    "mL": "*=",
    "dV": "/=",
    "rM": "%=",
    "aN": "&=",
    "oR": "|=",
    "eO": "^=",
    "ls": "<<",
    "rs": ">>",
    "lS": "<<=",
    "rS": ">>=",
    "eq": "==",
    "ne": "!=",
    "lt": "<",
    "gt": ">",
    "le": "<=",
    "ge": ">=",
    "ss": ".*",
    "sr": "->*",
    "pp": "++",
    "mm": "--",
    "pt": "->",
    "cl": "()",
    "ix": "[]",
}

# Operators whose spelling needs a space after the "operator" keyword.
_WORD_OPERATORS = {"new", "new[]", "delete", "delete[]"}

_UNARY_EXPRESSION_OPERATORS = {
    "ps": "+", "ng": "-", "ad": "&", "de": "*", "co": "~", "nt": "!",
}
_BINARY_EXPRESSION_OPERATORS = {
    "pl": "+", "mi": "-", "ml": "*", "dv": "/", "rm": "%",
    "an": "&", "or": "|", "eo": "^", "ls": "<<", "rs": ">>",
    "eq": "==", "ne": "!=", "lt": "<", "gt": ">", "le": "<=", "ge": ">=",
    "ss": ".*", "aS": "=", "aa": "&&", "oo": "||",
}
# "sr" is deliberately absent: inside an <expression> it starts an
# <unresolved-name> (Type::member), not the ->* operator, and is handled
# separately in _parse_expression.

_CTOR_DTOR = {
    "C1": KIND_CONSTRUCTOR,
    "C2": KIND_CONSTRUCTOR,
    "C3": KIND_CONSTRUCTOR,
    "D0": KIND_DESTRUCTOR,
    "D1": KIND_DESTRUCTOR,
    "D2": KIND_DESTRUCTOR,
}

_CV_SUFFIX = {"K": " const", "V": " volatile", "r": " restrict"}
_QUALIFIER_LETTERS = ("K", "V", "r")
_INTEGER_LITERAL_TYPES = {
    "int", "long", "unsigned int", "unsigned long", "long long",
    "unsigned long long", "__int128", "unsigned __int128", "bool",
    "char", "short", "wchar_t", "char16_t", "char32_t",
}


@dataclass
class _Name:
    """A parsed ``<name>``: qualified text plus classification."""

    qualified: str
    short: str
    namespace: str
    kind: str = KIND_FUNCTION
    is_template: bool = False
    own_template: bool = False
    has_return_type: bool = False
    cv: str = ""
    ref: str = ""


@dataclass
class _Encoding:
    """A parsed ``<encoding>``: name plus optional signature."""

    name: _Name
    parameters: tuple[str, ...] = ()
    return_type: str | None = None
    cv: str = ""
    ref: str = ""
    has_signature: bool = False


def _render_parameters(parameters: tuple[str, ...]) -> str:
    """Render a parameter list, dropping the ABI's ``void`` placeholder."""
    rendered = [item for item in parameters if item != "void"]
    return f"({', '.join(rendered)})"


def _pointer_or_reference_text(inner: str, marker: str) -> str:
    """Format ``P``/``R``/``O`` applied to ``inner``.

    A pointer or reference to a function type binds to the return type, so
    ``int(double)`` becomes ``int(*)(double)`` rather than ``int(double)*``.
    """
    suffix = {"P": "*", "R": "&", "O": "&&"}[marker]
    if inner.endswith(")") and "(" in inner:
        return_type, _, rest = inner.partition("(")
        return f"{return_type} ({suffix})({rest}"
    return f"{inner}{suffix}"


class _Demangler:
    """Recursive-descent parser for one mangled name."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0
        self._subs: list[str] = []
        self._known: set[str] = set()
        self._scopes: list[tuple[str, ...]] = []

    # -- cursor ---------------------------------------------------------
    def _eof(self) -> bool:
        return self._pos >= len(self._text)

    def _peek(self, count: int = 1) -> str:
        return self._text[self._pos : self._pos + count]

    def _advance(self, count: int = 1) -> str:
        chunk = self._text[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def _match(self, literal: str) -> bool:
        if self._text.startswith(literal, self._pos):
            self._pos += len(literal)
            return True
        return False

    def _expect(self, literal: str) -> None:
        if not self._match(literal):
            raise _DemangleError(
                f"expected {literal!r} at offset {self._pos} in {self._text!r}"
            )

    def _number(self) -> int:
        """``<number> ::= [n] <non-negative decimal integer>``"""
        negative = self._match("n")
        digits = ""
        while not self._eof() and self._peek().isdigit():
            digits += self._advance()
        if not digits:
            raise _DemangleError(f"expected a number at offset {self._pos}")
        value = int(digits)
        return -value if negative else value

    def _seq_id(self) -> int:
        """Base-36 sequence id terminated by ``_``; an empty id is 0."""
        digits = ""
        while not self._eof():
            char = self._peek()
            if char == "_":
                break
            if not (char.isdigit() or "A" <= char <= "Z"):
                raise _DemangleError(f"invalid sequence id at offset {self._pos}")
            digits += char
            self._advance()
        self._expect("_")
        return int(digits, 36) if digits else 0

    def _source_name(self) -> str:
        """``<source-name> ::= <positive length> <identifier>``"""
        length_text = ""
        while not self._eof() and self._peek().isdigit():
            length_text += self._advance()
        if not length_text:
            raise _DemangleError(f"expected a source-name length at offset {self._pos}")
        length = int(length_text)
        if length <= 0 or self._pos + length > len(self._text):
            raise _DemangleError(f"source-name length out of range at offset {self._pos}")
        return self._advance(length)

    # -- substitution ---------------------------------------------------
    def _add_candidate(self, text: str) -> None:
        """Register a name-level substitution candidate.

        The reference mangler only reaches its name registration after
        ``find_substitution`` has already failed, so a component that is already
        known is never registered twice: a duplicate entry would shift every
        later ``S<n>_`` index.
        """
        if text in self._known:
            return
        self._known.add(text)
        self._subs.append(text)

    def _add_type_candidate(self, text: str) -> None:
        """Register a type-level substitution candidate.

        Unlike names, the reference mangler registers every non-builtin type
        it writes without first checking for an existing entry, so the same
        type can occupy two indices (this happens when a template parameter
        resolves to a type that was already a candidate).
        """
        self._subs.append(text)

    def _parse_substitution(self) -> str:
        self._expect("S")
        head = self._peek()
        if head in _STANDARD_SUBSTITUTIONS:
            self._advance()
            return _STANDARD_SUBSTITUTIONS[head]
        if head == "_" or head.isdigit() or "A" <= head <= "Z":
            # S_ is candidate 0; S<n>_ is candidate n+1.
            seq = self._seq_id()
            index = 0 if head == "_" else seq + 1
            if not 0 <= index < len(self._subs):
                raise _DemangleError(f"substitution index {index} out of range")
            return self._subs[index]
        raise _DemangleError(f"invalid substitution at offset {self._pos}")

    # -- entry point ----------------------------------------------------
    def parse(self) -> DemangledSymbol:
        self._expect("_Z")
        if self._peek(3) == "GTt":
            # <special-name> ::= GTt <encoding>: transactional-memory clone.
            self._advance(3)
            return DemangledSymbol(
                display=(
                    "transaction clone for "
                    + self._build_symbol(self._parse_encoding()).display
                ),
                kind=KIND_SPECIAL,
                short_name="transaction clone",
            )
        if self._peek() in ("T", "G"):
            return self._parse_special_name()
        return self._build_symbol(self._parse_encoding())

    def _build_symbol(self, encoding: _Encoding) -> DemangledSymbol:
        name = encoding.name
        kind = name.kind
        if kind == KIND_FUNCTION:
            if not encoding.has_signature:
                # No parameter list means the encoding names data, not a call.
                kind = KIND_DATA
            elif name.namespace:
                kind = KIND_METHOD
        cv = encoding.cv or name.cv
        ref = encoding.ref or name.ref
        if encoding.has_signature:
            signature = _render_parameters(encoding.parameters)
        else:
            signature = ""
        display = f"{name.qualified}{signature}{cv}{ref}"
        # Constructors and destructors always return void; the ABI still
        # encodes a return type for constructor templates, and the reference
        # demanglers drop it rather than print a misleading one.
        if encoding.return_type and kind not in (KIND_CONSTRUCTOR, KIND_DESTRUCTOR):
            display = f"{encoding.return_type} {display}"
        return DemangledSymbol(
            display=display,
            kind=kind,
            qualified_name=name.qualified,
            namespace=name.namespace,
            short_name=name.short,
            parameters=encoding.parameters,
            return_type=encoding.return_type,
        )

    # -- encoding -------------------------------------------------------
    def _parse_encoding(self) -> _Encoding:
        """``<encoding> ::= <function name> <bare-function-type> | <name>``"""
        if self._peek() == "Z":
            return self._parse_local_name()
        scope_depth = len(self._scopes)
        name = self._parse_name()
        if self._eof() or self._peek() == "E":
            del self._scopes[scope_depth:]
            return _Encoding(name=name)
        parameters, return_type = self._parse_bare_function_type(
            include_return_type=name.own_template or name.has_return_type
        )
        del self._scopes[scope_depth:]
        return _Encoding(
            name=name,
            parameters=parameters,
            return_type=return_type,
            has_signature=True,
        )

    def _parse_bare_function_type(
        self, include_return_type: bool
    ) -> tuple[tuple[str, ...], str | None]:
        """``<bare-function-type> ::= [<return type>] <type>+``

        The return type is only encoded for function templates and conversion
        operators; ordinary functions carry parameter types alone.
        """
        return_type = self._parse_type() if include_return_type else None
        parameters: list[str] = []
        while not self._eof() and self._peek() != "E":
            parameters.append(self._parse_type())
        return tuple(parameters), return_type

    # -- local names ----------------------------------------------------
    def _parse_local_name(self) -> _Encoding:
        """``<local-name> ::= Z <function encoding> E <entity name> [disc]``"""
        self._expect("Z")
        function = self._parse_encoding()
        self._expect("E")
        if self._peek() == "s":
            self._advance()
            entity = _Name(
                qualified="string literal",
                short="string literal",
                namespace="",
            )
            entity_parameters: tuple[str, ...] = ()
            entity_has_signature = False
        else:
            entity = self._parse_name(as_type=True)
            if not self._eof() and self._peek() not in ("E", "_"):
                entity_parameters, _ = self._parse_bare_function_type(
                    include_return_type=entity.own_template
                )
                entity_has_signature = True
            else:
                entity_parameters = ()
                entity_has_signature = False
        self._consume_discriminator()
        function_text = self._build_symbol(function).display
        return _Encoding(
            name=_Name(
                qualified=f"{function_text}::{entity.qualified}",
                short=entity.short,
                namespace=function_text,
                kind=entity.kind,
            ),
            parameters=entity_parameters,
            has_signature=entity_has_signature,
        )

    def _consume_discriminator(self) -> None:
        if self._peek() != "_":
            return
        self._advance()
        while not self._eof() and (self._peek().isdigit() or "A" <= self._peek() <= "Z"):
            self._advance()

    # -- names ----------------------------------------------------------
    def _std_prefix_ahead(self) -> bool:
        """True when ``St`` starts an ``<unscoped-name>`` rather than a bare
        ``std`` substitution (i.e. it is followed by an identifier)."""
        if self._peek(2) != "St":
            return False
        if not self._peek(3)[2:]:
            return False
        if self._peek(3)[2].isdigit():
            return True
        two = self._peek(4)[2:]
        return (
            two in _OPERATORS
            or two in _CTOR_DTOR
            or two in ("Ut", "Ul", "Ue", "li")
        )

    def _parse_name(self, *, as_type: bool = False) -> _Name:
        head = self._peek()
        if head == "N":
            return self._parse_nested_name(as_type=as_type)
        if head == "Z":
            return self._parse_local_name().name
        if head == "S":
            if self._std_prefix_ahead():
                return self._parse_unscoped_name(as_type=as_type)
            text = self._parse_substitution()
            args = self._parse_template_args() if self._peek() == "I" else ""
            qualified = f"{text}{args}"
            if args:
                self._add_candidate(qualified)
            return _Name(
                qualified=qualified,
                short=qualified.rpartition("::")[2],
                namespace=qualified.rpartition("::")[0],
                is_template=bool(args),
                own_template=bool(args),
            )
        return self._parse_unscoped_name(as_type=as_type)

    def _parse_unscoped_name(self, *, as_type: bool) -> _Name:
        """``<unscoped-name> ::= <unqualified-name> | St <unqualified-name>``"""
        prefix = ""
        if self._match("St"):
            prefix = "std::"
        short, kind, has_return_type = self._parse_unqualified_name()
        qualified = f"{prefix}{short}"
        is_template = False
        if not self._eof() and self._peek() == "I":
            # <unscoped-template-name>: the template name is a candidate,
            # registered before its arguments.
            self._add_candidate(qualified)
            args = self._parse_template_args()
            qualified = f"{qualified}{args}"
            short = f"{short}{args}"
            is_template = True
        if as_type:
            # write_type() registers every non-builtin type after it is
            # complete; the name production itself registers nothing here.
            self._add_candidate(qualified)
        return _Name(
            qualified=qualified,
            short=short,
            namespace=qualified.rpartition("::")[0],
            kind=kind,
            is_template=is_template,
            own_template=is_template,
            has_return_type=has_return_type,
        )

    def _parse_nested_name(self, *, as_type: bool) -> _Name:
        """``<nested-name> ::= N [CV] [ref] <prefix> <unqualified-name> E``"""
        self._expect("N")
        cv = ""
        while self._peek() in _QUALIFIER_LETTERS:
            cv += _CV_SUFFIX[self._advance()]
        ref = ""
        if self._peek() == "R":
            self._advance()
            ref = " &"
        elif self._peek() == "O":
            self._advance()
            ref = " &&"

        parts: list[str] = []
        bare_parts: list[str] = []
        short = ""
        kind = KIND_FUNCTION
        has_return_type = False
        own_template = False
        while True:
            if self._eof():
                raise _DemangleError("unterminated nested name")
            if self._peek() == "E":
                self._advance()
                break
            component, component_kind, component_returns, is_reference = (
                self._parse_name_component()
            )
            parts.append(component)
            bare_parts.append(component)
            if not self._eof() and self._peek() == "I":
                # <template-prefix>: registered before its arguments. A
                # constructor/destructor template prefix is spelled with the
                # enclosing class name, matching the reference mangler.
                prefix_parts = list(parts)
                if component_kind in (KIND_CONSTRUCTOR, KIND_DESTRUCTOR):
                    prefix_parts[-1] = self._ctor_dtor_name(
                        component_kind, bare_parts[:-1]
                    )
                self._add_candidate("::".join(prefix_parts))
                parts[-1] = f"{component}{self._parse_template_args()}"
            if self._peek() == "E":
                # This component is the <unqualified-name>; only a template
                # name is a candidate, never the complete name.
                own_template = parts[-1] != component
                short = parts[-1]
                kind = component_kind
                has_return_type = component_returns
                self._advance()
                break
            if not is_reference:
                # A <prefix> level is a candidate once fully written.
                self._add_candidate("::".join(parts))
            short = parts[-1]
            kind = component_kind
            has_return_type = component_returns

        # Rebuild from components: a name whose template arguments contain
        # "::" (for example a constructor template) would otherwise be split
        # at the wrong place by a plain rpartition.
        prefix = "::".join(parts[:-1])
        if kind in (KIND_CONSTRUCTOR, KIND_DESTRUCTOR):
            # A ctor/dtor spells the enclosing class's unqualified name, and
            # keeps its own explicit template arguments:
            # "map<int>::~map()" and "B<int>::B<int>()", never "B<int>::C2()".
            class_name = self._ctor_dtor_name(kind, bare_parts[:-1])
            arguments = parts[-1][len(bare_parts[-1]) :]
            short = f"{class_name}{arguments}"
        else:
            short = parts[-1]
        qualified = f"{prefix}::{short}" if prefix else short
        if as_type:
            self._add_candidate(qualified)
        return _Name(
            qualified=qualified,
            short=short,
            namespace=prefix,
            kind=kind,
            is_template=own_template,
            own_template=own_template,
            has_return_type=has_return_type,
            cv=cv,
            ref=ref,
        )

    @staticmethod
    def _ctor_dtor_name(kind: str, enclosing: list[str]) -> str:
        """Spell a constructor/destructor as the enclosing class name."""
        if not enclosing:
            return "~" if kind == KIND_DESTRUCTOR else ""
        class_name = enclosing[-1].rpartition("::")[2]
        return f"~{class_name}" if kind == KIND_DESTRUCTOR else class_name

    def _parse_name_component(self) -> tuple[str, str, bool, bool]:
        """One ``<unqualified-name>`` (or substitution) inside a nested name.

        Returns the rendered component, its kind, whether it is a conversion
        operator (which forces an encoded return type), and whether it was a
        substitution reference (which is never a new candidate).
        """
        head = self._peek()
        if head.isdigit():
            return self._source_name(), KIND_FUNCTION, False, False
        if head == "S":
            return self._parse_substitution(), KIND_FUNCTION, False, True
        if head == "T":
            return self._parse_template_param(), KIND_FUNCTION, False, False
        if head == "U":
            if self._peek(2) == "Ut":
                self._advance(2)
                index = self._seq_id()
                return f"{{unnamed type#{index}}}", KIND_DATA, False, False
            if self._peek(2) == "Ul":
                # <unnamed-type-name> ::= Ul <lambda-sig> _ [disc]
                # <lambda-sig>       ::= <parameter-list> (the template-param
                #                      form is rare and omitted here)
                self._advance(2)
                parameters: list[str] = []
                while not self._eof() and self._peek() != "E":
                    parameters.append(self._parse_type())
                self._expect("E")
                self._expect("_")
                index = ""
                if self._peek().isdigit():
                    index = str(self._number())
                inner = ", ".join(parameters)
                return f"{{lambda({inner})#{index or 1}}}", KIND_DATA, False, False
            if self._peek(2) == "Ue":
                self._advance(2)
                underlying = self._parse_type()
                name = self._source_name()
                return f"{underlying}::{name}", KIND_DATA, False, False
            raise _DemangleError(f"unsupported unnamed type at offset {self._pos}")
        two = self._peek(2)
        if two in _CTOR_DTOR:
            self._advance(2)
            return two, _CTOR_DTOR[two], False, False
        if two == "cv":
            self._advance(2)
            # A conversion operator has no written return type: the target
            # type IS the "return", so it must not gain a "void" prefix.
            return f"operator {self._parse_type()}", KIND_OPERATOR, False, False
        if two == "li":
            self._advance(2)
            return f'operator""{self._source_name()}', KIND_OPERATOR, False, False
        if two in _OPERATORS:
            self._advance(2)
            spelling = _OPERATORS[two]
            label = (
                f"operator {spelling}"
                if spelling in _WORD_OPERATORS
                else f"operator{spelling}"
            )
            return label, KIND_OPERATOR, False, False
        raise _DemangleError(f"unsupported name component at offset {self._pos}")

    def _parse_unqualified_name(self) -> tuple[str, str, bool]:
        component, kind, returns = self._parse_name_component()[:3]
        tags = ""
        while self._peek() == "B":
            self._advance()
            tags += f"[abi: {self._source_name()}]"
        return f"{component}{tags}", kind, returns

    # -- template params and args ---------------------------------------
    def _parse_template_param(self) -> str:
        """``<template-param> ::= T_ | T <compact-number> _``

        The compact-number encoding is shared with substitutions: ``T_`` is
        parameter 0, ``T0_`` is parameter 1, ``T1_`` is parameter 2, ...

        Resolving a parameter substitutes the argument's mangled form, which
        the reference mangler emits through its type writer, so the resolved
        text becomes a substitution candidate in its own right.
        """
        self._expect("T")
        if self._match("_"):
            index = 0
        else:
            index = self._seq_id() + 1
        if not self._scopes or index >= len(self._scopes[-1]):
            # An out-of-range template parameter means the enclosing template
            # arguments are unknown, so the parameter type cannot be recovered.
            raise _DemangleError(
                f"template parameter {index} outside the current template scope"
            )
        resolved = self._scopes[-1][index]
        self._add_type_candidate(resolved)
        return resolved

    def _parse_template_args(self) -> str:
        self._expect("I")
        args: list[str] = []
        while not self._eof() and self._peek() != "E":
            if self._peek() == "J":
                self._advance()
                while not self._eof() and self._peek() != "E":
                    args.append(self._parse_template_arg())
                self._expect("E")
                continue
            args.append(self._parse_template_arg())
        self._expect("E")
        # The reference demanglers (GNU c++filt, cpp_demangle) insert a space
        # before the closing angle bracket only when the last argument already
        # ends with one, so that ">>" never reads as a shift operator. Matching
        # that convention keeps output diffable against those tools.
        joined = ", ".join(args)
        closer = " >" if joined.endswith(">") else ">"
        text = f"<{joined}{closer}"
        self._scopes.append(tuple(args))
        return text

    def _parse_template_arg(self) -> str:
        head = self._peek()
        if head == "X":
            self._advance()
            expression = self._parse_expression()
            self._expect("E")
            return expression
        if head == "L":
            return self._parse_expr_primary()
        if head == "D" and self._peek(2) in ("Dt", "DT", "Dp"):
            return self._parse_type()
        # A leading digit starts a <source-name> (a type); integer literals
        # always use the "L <type> <value> E" form, matching the reference
        # mangler, so a bare number is never a template argument.
        return self._parse_type()

    # -- types ----------------------------------------------------------
    def _parse_type(self) -> str:
        head = self._peek()
        if head in _QUALIFIER_LETTERS:
            self._advance()
            result = self._parse_type() + _CV_SUFFIX[head]
            self._add_type_candidate(result)
            return result
        if head in ("P", "R", "O"):
            self._advance()
            inner = self._parse_type()
            result = _pointer_or_reference_text(inner, head)
            self._add_type_candidate(result)
            return result
        if head == "C":
            self._advance()
            return f"{self._parse_type()} complex"
        if head == "G":
            self._advance()
            return f"{self._parse_type()} imaginary"
        if head == "M":
            self._advance()
            class_type = self._parse_type()
            member_type = self._parse_type()
            if member_type.endswith(")") and "(" in member_type:
                return_type, _, rest = member_type.partition("(")
                result = f"{return_type.strip()} ({class_type}::*)({rest}"
            else:
                result = f"{member_type} {class_type}::*"
            self._add_type_candidate(result)
            return result
        if head == "F":
            return self._parse_function_type()
        if head == "A":
            self._advance()
            if self._peek().isdigit() or (
                self._peek() == "n" and self._peek(2)[1:2].isdigit()
            ):
                dimension = str(self._number())
            else:
                dimension = self._parse_expression()
            self._expect("_")
            result = f"{self._parse_type()} [{dimension}]"
            self._add_type_candidate(result)
            return result
        if head == "T":
            param = self._parse_template_param()
            if self._peek() == "I":
                # <template-template-param> <template-args>: a template
                # parameter standing in for a template, instantiated here.
                result = f"{param}{self._parse_template_args()}"
                self._add_type_candidate(result)
                return result
            return param
        if head == "S":
            if self._std_prefix_ahead():
                scope_depth = len(self._scopes)
                result = self._parse_name(as_type=True).qualified
                del self._scopes[scope_depth:]
                return result
            text = self._parse_substitution()
            if self._peek() == "I":
                # <unscoped-template-name> ::= <substitution> <template-args>
                result = f"{text}{self._parse_template_args()}"
                self._add_type_candidate(result)
                return result
            return text
        # D-prefixed builtin types (char16_t, char32_t, nullptr_t, ...) must be
        # matched before the decltype/extended dispatch, otherwise every "D"
        # type is treated as an unsupported D-form.
        if self._peek(2) in _BUILTIN_TYPES_LONG:
            return _BUILTIN_TYPES_LONG[self._advance(2)]
        if head == "D":
            return self._parse_decltype_or_extended()
        if head == "U":
            self._advance()
            vendor = self._source_name()
            result = f"{self._parse_type()} {vendor}"
            self._add_type_candidate(result)
            return result
        if head == "u":
            self._advance()
            self._source_name()
            return self._parse_type()
        if head in _BUILTIN_TYPES:
            self._advance()
            return _BUILTIN_TYPES[head]
        scope_depth = len(self._scopes)
        result = self._parse_name(as_type=True).qualified
        del self._scopes[scope_depth:]
        return result

    def _parse_decltype_or_extended(self) -> str:
        self._expect("D")
        head = self._peek()
        if head in ("t", "T"):
            self._advance()
            expression = self._parse_expression()
            self._expect("E")
            return f"decltype({expression})"
        if head == "p":
            # Pack expansion: Dp <type>
            self._advance()
            return f"{self._parse_type()}..."
        if head == "v":
            self._advance()
            self._number()
            self._expect("_")
            return self._parse_type()
        raise _DemangleError(f"unsupported D-form at offset {self._pos}")

    def _parse_function_type(self) -> str:
        """``<function-type> ::= F [Y] <bare-function-type> [ref] E``"""
        self._expect("F")
        if self._peek() == "Y":
            self._advance()
        cv = ""
        while self._peek() in _QUALIFIER_LETTERS:
            cv += _CV_SUFFIX[self._advance()]
        return_type = self._parse_type()
        parameters: list[str] = []
        while not self._eof() and self._peek() != "E":
            parameters.append(self._parse_type())
        self._expect("E")
        ref = ""
        if self._peek() == "R":
            self._advance()
            ref = " &"
        elif self._peek() == "O":
            self._advance()
            ref = " &&"
        result = f"{return_type}{_render_parameters(tuple(parameters))}{cv}{ref}"
        self._add_type_candidate(result)
        return result

    # -- expressions ----------------------------------------------------
    def _parse_expression(self) -> str:
        two = self._peek(2)
        if two in _UNARY_EXPRESSION_OPERATORS:
            self._advance(2)
            return f"{_UNARY_EXPRESSION_OPERATORS[two]}({self._parse_expression()})"
        if two in _BINARY_EXPRESSION_OPERATORS:
            self._advance(2)
            left = self._parse_expression()
            right = self._parse_expression()
            return f"({left} {_BINARY_EXPRESSION_OPERATORS[two]} {right})"
        if two == "qu":
            self._advance(2)
            condition = self._parse_expression()
            when_true = self._parse_expression()
            when_false = self._parse_expression()
            return f"({condition} ? {when_true} : {when_false})"
        if two in ("cl", "ix"):
            self._advance(2)
            callee = self._parse_expression()
            args: list[str] = []
            while not self._eof() and self._peek() != "E":
                args.append(self._parse_expression())
            self._expect("E")
            return f"{callee}({', '.join(args)})"
        if two == "sr":
            # Unresolved name: <type> [E] <unqualified-name> [<template-args>],
            # e.g. a dependent member reference like QMetaTypeId2<T>::Defined.
            # The E is optional: the older mangling omitted it.
            self._advance(2)
            scope = self._parse_type()
            self._match("E")
            if self._peek() == "I":
                # <unscoped-template-name>: a substitution standing in for the
                # member's own name, instantiated with these arguments.
                name = f"{self._parse_substitution()}{self._parse_template_args()}"
            else:
                name = self._parse_name_component()[0]
            return f"{scope}::{name}"
        if two == "st":
            self._advance(2)
            return f"sizeof({self._parse_type()})"
        if two == "at":
            self._advance(2)
            return f"alignof({self._parse_type()})"
        if two in ("fp", "il", "fr", "fl", "ls", "sZ"):
            raise _DemangleError(f"unsupported expression form {two!r}")
        return self._parse_expr_primary()

    def _parse_expr_primary(self) -> str:
        head = self._peek()
        if head == "L":
            self._advance()
            type_name = self._parse_type()
            if type_name == "bool":
                # The ABI encodes booleans as 0/1; spell them as the source
                # did so template arguments read as conditions, not numbers.
                negative = self._match("n")
                value = self._number()
                if not negative and value in (0, 1):
                    literal = "true" if value else "false"
                else:
                    literal = str(-value if negative else value)
            elif type_name in _INTEGER_LITERAL_TYPES:
                negative = self._match("n")
                value = self._number()
                literal = str(-value if negative else value)
            else:
                literal = ""
                while not self._eof() and self._peek() != "E":
                    literal += self._advance()
            self._expect("E")
            return literal
        if head == "T":
            return self._parse_template_param()
        if head == "S":
            return self._parse_substitution()
        if head.isdigit() or (head == "n" and self._peek(2)[1:2].isdigit()):
            return str(self._number())
        return self._parse_name(as_type=True).qualified

    # -- special names --------------------------------------------------
    def _parse_special_name(self) -> DemangledSymbol:
        """``<special-name>`` for vtable, typeinfo, guard and thunk symbols."""
        # "TC" (construction vtable) and "TT" (VTT) both start with T, so the
        # two-letter code is matched before any single-letter consumption.
        if self._peek(2) == "TC":
            # <special-name> ::= TC <type> <offset-number> _ <type>
            self._advance(2)
            base = self._parse_type()
            self._number()
            self._expect("_")
            derived = self._parse_type()
            return DemangledSymbol(
                display=f"construction vtable for {base}-in-{derived}",
                kind=KIND_SPECIAL,
                qualified_name=base,
                short_name="construction vtable",
            )
        if self._peek() == "T":
            self._advance()
        head = self._peek(1)
        simple = {
            "V": ("vtable for", "vtable"),
            "T": ("VTT for", "VTT"),
            "I": ("typeinfo for", "typeinfo"),
            "S": ("typeinfo name for", "typeinfo name"),
        }
        if head in simple:
            self._advance()
            target = self._parse_type()
            label, short = simple[head]
            return DemangledSymbol(
                display=f"{label} {target}",
                kind=KIND_SPECIAL,
                qualified_name=target,
                short_name=short,
            )
        if head in ("W", "H"):
            self._advance()
            target = self._build_symbol(self._parse_encoding()).display
            label = "TLS wrapper for" if head == "W" else "TLS init for"
            short = "TLS wrapper" if head == "W" else "TLS init"
            return DemangledSymbol(
                display=f"{label} {target}",
                kind=KIND_SPECIAL,
                qualified_name=target,
                short_name=short,
            )
        if head == "G":
            self._advance()
            marker = self._peek(1)
            self._advance()
            target = self._parse_name().qualified
            if marker == "V":
                return DemangledSymbol(
                    display=f"guard variable for {target}",
                    kind=KIND_SPECIAL,
                    qualified_name=target,
                    short_name="guard variable",
                )
            self._expect("_")
            return DemangledSymbol(
                display=f"reference temporary for {target}",
                kind=KIND_SPECIAL,
                qualified_name=target,
                short_name="reference temporary",
            )
        if head == "c":
            self._advance()
            self._parse_call_offset()
            self._parse_call_offset()
            base = self._build_symbol(self._parse_encoding()).display
            return DemangledSymbol(
                display=f"construction vtable for {base}",
                kind=KIND_SPECIAL,
                qualified_name=base,
                short_name="construction vtable",
            )
        if head in ("h", "v"):
            self._advance()
            offset = self._parse_call_offset()
            if head == "v":
                # Covariant-return thunks carry a second (virtual) offset.
                offset = self._parse_call_offset()
            base = self._build_symbol(self._parse_encoding()).display
            return DemangledSymbol(
                display=f"virtual thunk to {base} ({offset})",
                kind=KIND_SPECIAL,
                qualified_name=base,
                short_name="virtual thunk",
            )
        offset = self._parse_call_offset()
        base = self._build_symbol(self._parse_encoding()).display
        return DemangledSymbol(
            display=f"non-virtual thunk to {base} ({offset})",
            kind=KIND_SPECIAL,
            qualified_name=base,
            short_name="non-virtual thunk",
        )

    def _parse_call_offset(self) -> int:
        """``<call-offset> ::= n <number> _ | <number> [_]``"""
        if self._match("n"):
            offset = -self._number()
        else:
            offset = self._number()
        self._match("_")
        return offset


def demangle(mangled: str) -> DemangledSymbol:
    """Demangle an Itanium C++ symbol name.

    Never raises. Names that are not Itanium-mangled come back with
    ``kind == "unmangled"`` and their original text; mangled names outside the
    supported subset come back with ``kind == "undecoded"``.
    """
    text = mangled.strip()
    if not text.startswith("_Z"):
        return DemangledSymbol(
            display=text,
            kind=KIND_UNMANGLED,
            qualified_name=text,
            short_name=text,
            language="c",
        )
    try:
        return _Demangler(text).parse()
    except (_DemangleError, IndexError, ValueError, RecursionError):
        return DemangledSymbol(
            display=text,
            kind=KIND_UNDECODED,
            qualified_name=text,
            short_name=text,
        )
