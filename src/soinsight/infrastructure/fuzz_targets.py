"""Fuzz-target candidates from static entry-point facts.

The module ranks the functions a fuzzer could reasonably drive, using only what
the symbol table and the recovered signatures already say: an exported function
is reachable, a JNI method is reachable *and* takes a Java-side argument list, a
name like ``parse``/``decode``/``read`` suggests input processing, and a
pointer-plus-length parameter pair is what a fuzzer can actually feed.

Every candidate reports the evidence behind its rank. The score is a heuristic
ordering device, not a claim that the function is fuzzable, and the parameters
are typed by *shape* (buffer, size, out-pointer, struct, callback, scalar) rather
than by a real data-flow analysis.
"""

import re
from dataclasses import dataclass

__all__ = ["FuzzCandidate", "FuzzReport", "rank_candidates"]

#: Type spellings that are a size/count argument on their own.
_SIZE_TYPES = frozenset(
    {
        "size_t",
        "ssize_t",
        "std::size_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uintptr_t",
        "intptr_t",
        "unsigned int",
        "unsigned long",
        "unsigned long long",
        "unsigned short",
    }
)

#: Ambiguous integer types: only a size-ish *name* makes them a length.
_AMBIGUOUS_INT_TYPES = frozenset(
    {"int", "long", "short", "unsigned", "char", "unsigned char", "signed int"}
)

_SIZE_NAMES = tuple(
    {"len", "length", "size", "count", "n", "cap", "capacity", "num", "bytes"}
)

_PARSER_NAME = re.compile(
    r"(parse|decode|read|load|process|handle|unpack|deserial|extract|verify|"
    r"scan|consume|convert|inflate|decompress|fuzz)",
    re.IGNORECASE,
)

# Score weights, kept in one place so the ranking is auditable.
_SCORE_JNI = 45
_SCORE_PARSER = 35
_SCORE_EXPORT = 10
_SCORE_BUFFER_LENGTH = 25
_SCORE_POINTER = 5
_SCORE_POINTER_CAP = 15
_SCORE_NO_PARAMETERS = -10
_SCORE_CALLBACK = -5


@dataclass(frozen=True)
class ParameterShape:
    """One parameter classified by shape."""

    index: int
    name: str
    type: str
    role: str


@dataclass(frozen=True)
class FuzzCandidate:
    """One function a fuzzer could drive, with the evidence for its rank."""

    name: str
    linkage_name: str
    signature: str
    kind: str
    """``jni``, ``parser`` or ``export``."""

    language: str
    parameters: tuple[ParameterShape, ...]
    buffer_length_pairs: int
    score: int
    reasons: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "linkage_name": self.linkage_name,
            "signature": self.signature,
            "kind": self.kind,
            "language": self.language,
            "parameter_count": len(self.parameters),
            "parameters": [
                {
                    "index": item.index,
                    "name": item.name,
                    "type": item.type,
                    "role": item.role,
                }
                for item in self.parameters
            ],
            "buffer_length_pairs": self.buffer_length_pairs,
            "score": self.score,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class FuzzReport:
    """Ranked candidates plus the counts the report quotes."""

    candidates: tuple[FuzzCandidate, ...]

    @property
    def jni_count(self) -> int:
        return sum(1 for item in self.candidates if item.kind == "jni")

    @property
    def parser_like_count(self) -> int:
        return sum(1 for item in self.candidates if item.kind == "parser")

    @property
    def buffer_length_pair_count(self) -> int:
        return sum(1 for item in self.candidates if item.buffer_length_pairs)


def _is_size(parameter: dict) -> bool:
    """Tell whether a parameter is a length/count.

    ``size_t`` and the fixed-width integers are lengths by type; ``int mode`` is
    not, so a plain ``int`` only counts when its name says it is one.
    """
    type_name = str(parameter.get("type") or "").strip()
    normalized = " ".join(type_name.replace("const ", "").split())
    if normalized in _SIZE_TYPES:
        return True
    if normalized not in _AMBIGUOUS_INT_TYPES:
        return False
    name = str(parameter.get("name") or "").strip().lower()
    return name in _SIZE_NAMES


def _classify(parameters: list[dict]) -> tuple[tuple[ParameterShape, ...], int, list[str]]:
    shapes: list[ParameterShape] = []
    reasons: list[str] = []
    buffer_indexes: list[int] = []
    size_indexes: list[int] = []

    for index, parameter in enumerate(parameters):
        type_name = str(parameter.get("type") or "").strip()
        name = str(parameter.get("name") or "").strip()
        lowered = type_name.lower()

        if "(*)" in type_name or "function" in lowered:
            role = "callback"
        elif "**" in type_name:
            role = "out-pointer"
        elif "*" in type_name or "[]" in type_name:
            role = "buffer"
            buffer_indexes.append(index)
        elif "struct " in lowered or "class " in lowered or "union " in lowered:
            role = "struct"
        elif _is_size(parameter):
            role = "size"
            size_indexes.append(index)
        else:
            role = "scalar"

        shapes.append(
            ParameterShape(index=index, name=name, type=type_name, role=role)
        )

    # A buffer followed by a size (in any order) is what a fuzzer can drive.
    pairs = 0
    for buffer_index in buffer_indexes:
        if any(size_index > buffer_index for size_index in size_indexes) or any(
            size_index < buffer_index for size_index in size_indexes
        ):
            pairs += 1
    if pairs:
        reasons.append(f"含 {pairs} 组「缓冲区 + 长度」参数")
    return tuple(shapes), pairs, reasons


def _score(kind: str, shapes: tuple[ParameterShape, ...], pairs: int) -> tuple[int, list[str]]:
    reasons: list[str] = []
    if kind == "jni":
        score = _SCORE_JNI
        reasons.append("JNI 导出（Java 侧可直达）")
    elif kind == "parser":
        score = _SCORE_PARSER
        reasons.append("名称含解析/读取类语义")
    else:
        score = _SCORE_EXPORT
        reasons.append("导出函数（可被外部调用）")

    if pairs:
        score += _SCORE_BUFFER_LENGTH
        reasons.append("可直接喂入数据")
    pointer_count = sum(1 for item in shapes if item.role in ("buffer", "out-pointer"))
    if pointer_count:
        score += min(_SCORE_POINTER * pointer_count, _SCORE_POINTER_CAP)
        reasons.append(f"{pointer_count} 个指针参数")
    if not shapes:
        score += _SCORE_NO_PARAMETERS
        reasons.append("无参数（驱动的输入面很小）")
    if any(item.role == "callback" for item in shapes):
        score += _SCORE_CALLBACK
        reasons.append("含回调参数（需要额外桩）")
    return max(0, min(score, 100)), reasons


def rank_candidates(
    exported_functions: tuple[dict, ...],
    type_signatures: tuple[dict, ...],
    *,
    max_targets: int = 50,
    min_score: int = 0,
) -> FuzzReport:
    """Rank exported functions and JNI methods as fuzz targets."""
    types_by_name: dict[str, tuple[dict, ...]] = {}
    for record in type_signatures:
        for key in (record.get("name"), record.get("linkage_name")):
            if key:
                types_by_name.setdefault(str(key), tuple(record.get("parameters") or ()))

    candidates: list[FuzzCandidate] = []
    seen: set[str] = set()
    for record in exported_functions:
        raw_name = str(record.get("name") or "")
        if not raw_name or raw_name in seen:
            continue
        seen.add(raw_name)
        if str(record.get("kind") or "function") != "function":
            continue
        if str(record.get("bind") or "").upper() == "STB_LOCAL":
            continue

        merged = types_by_name.get(raw_name) or types_by_name.get(
            str(record.get("signature") or "")
        )
        parameters = list(merged) if merged is not None else list(
            record.get("parameters") or ()
        )
        shapes, pairs, reasons = _classify(parameters)

        jni = record.get("jni")
        short_name = str(record.get("short_name") or raw_name)
        if jni:
            kind = "jni"
        elif _PARSER_NAME.search(short_name) or _PARSER_NAME.search(raw_name):
            kind = "parser"
        else:
            kind = "export"

        score, score_reasons = _score(kind, shapes, pairs)
        if score < min_score:
            continue
        candidates.append(
            FuzzCandidate(
                name=short_name,
                linkage_name=raw_name,
                signature=str(record.get("signature") or raw_name),
                kind=kind,
                language=str(record.get("language") or "c"),
                parameters=shapes,
                buffer_length_pairs=pairs,
                score=score,
                reasons=tuple(score_reasons + reasons),
            )
        )

    candidates.sort(key=lambda item: (-item.score, item.linkage_name))
    return FuzzReport(candidates=tuple(candidates[:max_targets]))
