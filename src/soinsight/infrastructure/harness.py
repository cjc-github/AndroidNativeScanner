"""Generate a fuzz harness skeleton from recovered static facts.

The generator turns a ranked entry point and its parameter shapes into compilable
C for a libFuzzer-style driver. It is a *template*: the first buffer parameter
receives the fuzz input, length parameters receive its size, everything else gets
a zero value, and parameters the generator cannot satisfy (a second buffer,
callbacks, output pointers) are reported as warnings instead of being guessed.

The output is source text, so nothing here executes the target; compiling and
running it stays a deliberate human step.
"""

from dataclasses import dataclass

__all__ = ["HarnessDraft", "build_harness"]

_ENGINES = frozenset({"libfuzzer"})

_ZERO_VALUES = {
    "size": "size",
    "scalar": "0",
    "struct": "{0}",
}


@dataclass(frozen=True)
class HarnessDraft:
    """One generated harness and what the generator could not satisfy."""

    target: str
    linkage_name: str
    engine: str
    source: str
    warnings: tuple[str, ...]
    template: bool = True

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "linkage_name": self.linkage_name,
            "engine": self.engine,
            "language": "c",
            "template": self.template,
            "warnings": list(self.warnings),
            "source": self.source,
        }


def _is_plain_c_signature(signature: str) -> bool:
    """A prototype is only worth emitting when it is plain C."""
    return bool(signature) and "(" in signature and signature.endswith(")") and not any(
        marker in signature for marker in ("::", "<", ">")
    )


def _prototype(candidate: dict, signature: str) -> tuple[str | None, str | None]:
    """Return the extern declaration to emit, plus a warning when it is a guess.

    Both recovered signature forms already carry a return type
    (``int parse(...)``), so the common case is ``extern <signature>;``. A bare
    ``name(...)`` without one is not valid C, so the template uses the
    ``return_type`` metadata when it exists and states the ``int`` assumption
    when it does not.
    """
    if not _is_plain_c_signature(signature):
        return None, "恢复出的签名不是纯 C 形式，模板未声明原型，需人工补充 extern 声明"
    if " " in signature.split("(", 1)[0]:
        # Something precedes the function name: that is the return type.
        return f"extern {signature};", None
    return_type = str(candidate.get("return_type") or "").strip()
    if return_type:
        return f"extern {return_type} {signature};", None
    return f"extern int {signature};", (
        "恢复出的签名没有返回类型（DWARF 未提供），模板按 int 假设，需人工确认"
    )


def _call_arguments(candidate: dict) -> tuple[list[str], list[str]]:
    """Map each parameter to a C expression, collecting what cannot be fed."""
    arguments: list[str] = []
    warnings: list[str] = []
    buffer_assigned = False

    for parameter in candidate.get("parameters") or ():
        role = str(parameter.get("role") or "scalar")
        type_name = str(parameter.get("type") or "int").strip() or "int"
        name = str(parameter.get("name") or f"arg{parameter.get('index')}")

        if role == "buffer" and not buffer_assigned:
            arguments.append("(const void *)data")
            buffer_assigned = True
            continue
        if role == "buffer":
            arguments.append("NULL")
            warnings.append(
                f"参数 {name}（{type_name}）是第二个缓冲区，模板只喂第一个，需人工补数据"
            )
            continue
        if role == "callback":
            arguments.append("NULL")
            warnings.append(f"参数 {name}（{type_name}）是回调，模板传 NULL，需人工写桩")
            continue
        if role == "out-pointer":
            arguments.append("NULL")
            warnings.append(
                f"参数 {name}（{type_name}）是输出指针，模板传 NULL，需人工指定可写缓冲区"
            )
            continue
        arguments.append(_ZERO_VALUES.get(role, "0"))

    if not buffer_assigned:
        warnings.append(
            "该入口没有缓冲区参数，模板不会把 fuzz 数据喂进去；建议改用解析类入口"
        )
    elif "size" not in arguments:
        # ``size`` only appears when a parameter was classified as a length, so a
        # fed buffer without one keeps a literal 0 and the harness would fuzz
        # nothing meaningful.
        warnings.append(
            "把数据喂给了缓冲区，但没有识别到长度参数，模板传的是 0；"
            "若该入口按长度判断边界，需人工改成 size"
        )
    return arguments, warnings


def build_harness(candidate: dict, *, engine: str = "libfuzzer") -> HarnessDraft:
    """Generate a harness source for one fuzz-target candidate."""
    if engine not in _ENGINES:
        raise ValueError(f"Unsupported harness engine: {engine}")

    target = str(candidate.get("name") or "target")
    linkage_name = str(candidate.get("linkage_name") or target)
    signature = str(candidate.get("signature") or "").strip()
    arguments, warnings = _call_arguments(candidate)
    call = f"{linkage_name}({', '.join(arguments)})"
    declaration, declaration_warning = _prototype(candidate, signature)
    if declaration_warning:
        warnings.append(declaration_warning)

    lines = [
        "/* Generated by SOInsight automation.harness -- a template, not a finished",
        " * harness: review the argument mapping, then compile and run it yourself.",
        " */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
    ]
    if declaration:
        lines.extend([declaration, ""])
    else:
        lines.extend(
            [
                f"/* Recovered call shape: {signature or linkage_name + '(...)'} */",
                "/* Not plain C, so no prototype was emitted; declare it yourself. */",
                "",
            ]
        )
    lines.extend(
        [
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
            "    if (size == 0) {",
            "        return 0;",
            "    }",
            f"    {call};",
            "    return 0;",
            "}",
            "",
        ]
    )
    return HarnessDraft(
        target=target,
        linkage_name=linkage_name,
        engine=engine,
        source="\n".join(lines),
        warnings=tuple(warnings),
    )
