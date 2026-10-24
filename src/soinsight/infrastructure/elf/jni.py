"""JNI native-method name decoder.

JNI exports follow a reversible text encoding rather than the C++ ABI:
``Java_<mangled package>_<mangled class>_<mangled method>`` where ``.`` becomes
``_``, ``_`` becomes ``_1``, ``;`` becomes ``_2`` and ``[`` becomes ``_3``.
Overloaded native methods append ``__`` followed by the mangled argument
signature.

Because a literal underscore always escapes to ``_1``, a bare ``__`` in the
symbol unambiguously marks the overload separator, so the split is exact.

Decoding a JNI symbol recovers the Java package, class, method and — for
overloads — the full argument and return types, which is the only signature
information a native library retains for its Java-facing entry points.
"""

from __future__ import annotations

from dataclasses import dataclass


_JNI_PREFIX = "Java_"

_ESCAPES = {"_1": "_", "_2": ";", "_3": "["}
_ESCAPE_DIGITS = "123"

_PRIMITIVE_TYPES = {
    "B": "byte",
    "C": "char",
    "D": "double",
    "F": "float",
    "I": "int",
    "J": "long",
    "S": "short",
    "Z": "boolean",
    "V": "void",
}


@dataclass(frozen=True)
class JniSymbol:
    """A decoded JNI native method name."""

    package: str
    class_name: str
    method: str
    parameters: tuple[str, ...] = ()
    return_type: str | None = None

    @property
    def qualified_name(self) -> str:
        if self.package:
            return f"{self.package}.{self.class_name}.{self.method}"
        return f"{self.class_name}.{self.method}"

    @property
    def signature(self) -> str:
        """Human-readable signature, e.g. ``void method(int, String[])``.

        The JNI mangled name never carries a return type, so the return type is
        only present when the producer emitted a full JVM descriptor.
        """
        if not self.parameters and self.return_type is None:
            return self.qualified_name
        rendered = ", ".join(self.parameters)
        prefix = f"{self.return_type} " if self.return_type else ""
        return f"{prefix}{self.qualified_name}({rendered})"


def decode_jni_symbol(name: str) -> JniSymbol | None:
    """Decode a JNI native method symbol, or return ``None`` if it is not one."""
    if not name.startswith(_JNI_PREFIX):
        return None
    body = name[len(_JNI_PREFIX) :]
    if not body:
        return None

    parameters: tuple[str, ...] = ()
    return_type: str | None = None
    overload_at = body.find("__")
    if overload_at != -1:
        # A literal underscore always escapes to "_1", so a bare "__" in the
        # mangled name unambiguously marks the overload separator.
        candidate = _unescape(body[overload_at + 2 :])
        parsed = _parse_overload_signature(candidate)
        if parsed is not None:
            parameters, return_type = parsed
            body = body[:overload_at]

    decoded = _unescape(body)
    parts = _split_escaped(body)
    if len(parts) < 2 or not all(parts):
        # Every component must be non-empty: the escaping rules guarantee that
        # a well-formed JNI name never produces an empty component.
        return None
    method = parts[-1]
    class_name = parts[-2]
    package = ".".join(parts[:-2])

    return JniSymbol(
        package=package,
        class_name=class_name,
        method=method,
        parameters=parameters,
        return_type=return_type,
    )


def _parse_overload_signature(text: str) -> tuple[tuple[str, ...], str | None] | None:
    """Parse an overload suffix, which is the mangled parameter type list.

    The JNI specification appends the parameter types only: no enclosing
    parentheses and no return type, so the return type stays unknown. A
    parenthesised JVM descriptor is also accepted when a producer emits one.
    """
    if text.startswith("("):
        close = text.find(")")
        if close == -1:
            return None
        parameters = _parse_type_list(text[1:close])
        if parameters is None:
            return None
        return_type = _parse_type_list(text[close + 1 :])
        return parameters, (return_type[0] if return_type else None)
    parameters = _parse_type_list(text)
    if parameters is None or not parameters:
        return None
    return parameters, None


def _parse_type_list(text: str) -> tuple[str, ...] | None:
    """Parse a concatenation of JVM field types, or ``None`` if malformed."""
    types: list[str] = []
    index = 0
    while index < len(text):
        parsed, index = _parse_field_type(text, index)
        if parsed is None:
            return None
        types.append(parsed)
    return tuple(types)


def _unescape(text: str) -> str:
    for escaped, literal in _ESCAPES.items():
        text = text.replace(escaped, literal)
    return text


def _split_escaped(text: str) -> list[str]:
    """Split a mangled name on separators, honouring the escape sequences.

    ``_`` separates the package, class and method components, but ``_1``,
    ``_2`` and ``_3`` are escapes for a literal ``_``, ``;`` and ``[`` inside a
    component, so a naive ``split("_")`` would break names such as
    ``My_1Class``. Splitting must happen before unescaping.
    """
    parts: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "_" and index + 1 < len(text) and text[index + 1] in _ESCAPE_DIGITS:
            current.append(_ESCAPES[text[index : index + 2]])
            index += 2
            continue
        if char == "_":
            parts.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _parse_field_type(text: str, index: int) -> tuple[str | None, int]:
    """Parse one JVM field type at ``index``; ``None`` means malformed."""
    dimensions = 0
    while index < len(text) and text[index] == "[":
        dimensions += 1
        index += 1
    if index >= len(text):
        return None, index

    char = text[index]
    if char == "L":
        end = text.find(";", index)
        if end == -1:
            return None, index
        # Package separators were mangled to "_" alongside "."; after
        # unescaping they are indistinguishable, so both mean a package
        # boundary in a class name.
        class_name = text[index + 1 : end].replace("_", ".")
        index = end + 1
    elif char in _PRIMITIVE_TYPES:
        class_name = _PRIMITIVE_TYPES[char]
        index += 1
    else:
        return None, index

    if dimensions:
        class_name += "[]" * dimensions
    return class_name, index
