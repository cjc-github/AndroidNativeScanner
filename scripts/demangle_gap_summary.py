"""Final gap analysis: exactly which constructs the project demangler cannot decode.

Root causes confirmed by bisection against cpp_demangle on 40,948 mangled symbols
from the 21 sample .so files.
"""

from __future__ import annotations

import re
from pathlib import Path

from elftools.elf.elffile import ELFFile

from soinsight.infrastructure.elf.demangle import demangle

MANGLED = re.compile(r"^_Z")
D_CODES = ("Ds", "Di", "Du", "Dn", "Da", "Dc", "DF")
SPECIAL_PREFIXES = ("_ZTC", "_ZTI", "_ZTS", "_ZTT", "_ZTV", "_ZTh", "_ZTv")


def iter_symbols(path: Path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for table in (".dynsym", ".symtab"):
            section = elf.get_section_by_name(table)
            if section is None:
                continue
            for symbol in section.iter_symbols():
                name = symbol.name
                if name and MANGLED.match(name):
                    yield name


def bucket(name: str) -> str:
    if any(code in name for code in D_CODES):
        return "D-extended builtin type"
    if any(name.startswith(p) for p in SPECIAL_PREFIXES):
        return "special name (ZTC/ZTI/ZTS/thunk)"
    body = name[2:]
    for op in ("pp", "mm", "pt"):
        if re.search(rf"(?<=[A-Za-z_]){op}(?=[A-Z]|$|v$|i$|E)", body):
            return f"missing operator '{op}'"
    if "Xa" in name:
        return "address-of expression 'Xa'"
    return "UNCLASSIFIED"


counts: dict[str, int] = {}
unclassified: list[str] = []
total_mangled = 0
total_failed = 0

for path in sorted(Path("in").glob("*.so")):
    for name in iter_symbols(path):
        total_mangled += 1
        result = demangle(name)
        if result.kind != "undecoded":
            continue
        total_failed += 1
        key = bucket(name)
        counts[key] = counts.get(key, 0) + 1
        if key == "UNCLASSIFIED":
            unclassified.append(name)

print(f"mangled symbols scanned : {total_mangled}")
print(f"undecoded               : {total_failed}  ({total_failed / total_mangled * 100:.2f}%)")
print(f"decoded                 : {total_mangled - total_failed}")
print()
print("failure buckets:")
for key, value in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"  {value:4d}  {key}")
print(f"\nUNCLASSIFIED: {len(unclassified)}")
for name in unclassified:
    print(f"  {name}")
