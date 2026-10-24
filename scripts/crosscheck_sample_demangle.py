"""Cross-validate the project demangler against cpp_demangle on the sample .so files.

For every mangled symbol in every input .so, run both demanglers and classify:
  - both_fail      : neither could demangle
  - ours_only      : project demangled, reference could not
  - ref_only       : reference demangled, project could not
  - both_ok_same   : both demangled, identical text
  - both_ok_diff   : both demangled, different text
  - ours_no_params : project demangled but the result carries no parameter list

Writes a JSON summary to stdout.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import cpp_demangle
from elftools.elf.elffile import ELFFile

from soinsight.infrastructure.elf.demangle import demangle

MANGLED = re.compile(r"^_Z")


def iter_exported_symbols(path: Path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for table_name in (".dynsym", ".symtab"):
            section = elf.get_section_by_name(table_name)
            if section is None:
                continue
            for symbol in section.iter_symbols():
                name = symbol.name
                if not name or not MANGLED.match(name):
                    continue
                if symbol["st_info"]["type"] not in ("STT_FUNC", "STT_GNU_IFUNC", "STT_NOTYPE"):
                    continue
                if symbol["st_shndx"] == "SHN_UNDEF":
                    continue
                yield name


def ref_demangle(name: str) -> str | None:
    try:
        return cpp_demangle.demangle(name)
    except Exception:
        return None


def classify(name: str) -> tuple[str, object, str | None]:
    result = demangle(name)
    ours = result.display
    ours_failed = result.kind == "undecoded"
    theirs = ref_demangle(name)
    theirs_failed = theirs is None

    if ours_failed and theirs_failed:
        bucket = "both_fail"
    elif ours_failed:
        bucket = "ref_only"
    elif theirs_failed:
        bucket = "ours_only"
    elif ours == theirs:
        bucket = "both_ok_same"
    else:
        bucket = "both_ok_diff"

    # A decoded function signature must carry a parameter list; a bare
    # qualified name means the mangling was not fully understood.
    if not ours_failed and result.kind == "function" and "(" not in ours:
        bucket = "ours_no_params"

    return bucket, result, theirs


def main() -> None:
    root = Path("in")
    summary: dict[str, object] = {}
    details: dict[str, list] = {}

    for path in sorted(root.glob("*.so")):
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        for name in iter_exported_symbols(path):
            bucket, ours, theirs = classify(name)
            counts[bucket] = counts.get(bucket, 0) + 1
            if bucket in (
                "both_fail",
                "ref_only",
                "ours_only",
                "ours_no_params",
                "both_ok_diff",
            ):
                samples.setdefault(bucket, []).append(name)
        summary[path.name] = counts
        details[path.name] = samples
        print(f"{path.name}: {counts}", flush=True)

    total: dict[str, int] = {}
    for counts in summary.values():
        for key, value in counts.items():
            total[key] = total.get(key, 0) + value

    print("\nTOTAL:", json.dumps(total, indent=2, sort_keys=True))

    out = Path("in") / "demangle-crosscheck.json"
    out.write_text(
        json.dumps({"summary": summary, "total": total, "samples": details}, indent=2),
        encoding="utf-8",
    )
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
