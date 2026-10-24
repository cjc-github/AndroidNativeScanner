"""Validate the demangler against real shared libraries from manylinux wheels.

Downloads wheels that bundle C++ shared libraries (libproj and friends), then
for every exported function compares this implementation's demangling with the
``cpp_demangle`` reference implementation.

Usage:
    python scripts/categorise_real_sos.py

This is a development aid, not part of the test suite: the same corpus is
asserted by tests/unit/test_demangler_oracle.py, which skips when the
development dependency is absent.

Note that Python extension modules are deliberately excluded: they are built
with hidden visibility and export only their ``PyInit_*`` entry point, so they
carry almost no C++ symbols to check.
"""

import re
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, "src")

import cpp_demangle  # noqa: E402

from soinsight.infrastructure.elf import demangle, parse_elf  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
WHEEL_DIR = ROOT / "tmp_wheels"
EXTRACT_DIR = ROOT / "tmp_sos"

# Wheels that bundle real C++ shared libraries.
WHEELS = ("pyproj",)


def download() -> None:
    WHEEL_DIR.mkdir(exist_ok=True)
    for wheel in WHEELS:
        subprocess.run(
            [
                sys.executable, "-m", "pip", "download", "--no-deps",
                "--only-binary=:all:", "--platform", "manylinux2014_x86_64",
                "--python-version", "310", "--implementation", "cp",
                wheel, "-d", str(WHEEL_DIR),
            ],
            check=True,
            capture_output=True,
        )


def extract() -> list[Path]:
    EXTRACT_DIR.mkdir(exist_ok=True)
    found: list[Path] = []
    for wheel in sorted(WHEEL_DIR.glob("*.whl")):
        target = EXTRACT_DIR / wheel.stem
        target.mkdir(exist_ok=True)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(target)
        found.extend(sorted(target.rglob("*.so*")))
    return found


def oracle(name: str) -> str | None:
    try:
        return cpp_demangle.demangle(name)
    except Exception:  # noqa: BLE001
        return None


def normalise(text: str) -> str:
    """Collapse cosmetic differences: spacing and special-name formats."""
    text = re.sub(r"\s+>", ">", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"^\{vtable\((.+)\)\}$", r"vtable for \1", text)
    text = re.sub(r"^\{vtt\((.+)\)\}$", r"VTT for \1", text)
    text = re.sub(
        r"^\{virtual override thunk\(\{offset\((-?\d+)\)\}, (.+)\)\}$",
        r"virtual thunk to \2 (\1)",
        text,
    )
    text = re.sub(
        r"^\{virtual override thunk\(\{virtual offset\((-?\d+), (-?\d+)\)\}, (.+)\)\}$",
        r"virtual thunk to \3 (\2)",
        text,
    )
    text = re.sub(r"^reference temporary #\d+ for ", "reference temporary for ", text)
    return text


def classify(ours: str, expected: str) -> str:
    """Bucket a divergence so display conventions are split from real bugs."""
    if normalise(ours) == normalise(expected):
        return "special-name display format"
    if "T" + "_" in ours or re.search(r"\bT\d+_\b", ours):
        return "unresolved template parameter"
    if ours.count("<") != expected.count("<"):
        return "template arity"
    if re.sub(r"[<>,&*()\[\]:]", "", ours) == re.sub(
        r"[<>,&*()\[\]:]", "", expected
    ):
        return "separator rendering"
    ours_ids = sorted(re.findall(r"[A-Za-z_]\w*", ours))
    expected_ids = sorted(re.findall(r"[A-Za-z_]\w*", expected))
    if ours_ids == expected_ids:
        return "same identifiers, different nesting"
    return "structural"


def main() -> int:
    if not list(WHEEL_DIR.glob("*.whl")):
        download()
    libraries = [path for path in extract() if "linux-gnu" not in path.name]

    buckets: Counter[str] = Counter()
    examples: dict[str, list[tuple[str, str, str]]] = {}
    totals: Counter[str] = Counter()

    for library in libraries:
        try:
            elf = parse_elf(library)
        except Exception:  # noqa: BLE001
            continue
        exports = [
            symbol
            for symbol in elf.symbols_from(".dynsym")
            if symbol.is_exported and symbol.is_function
        ]
        totals["libraries"] += 1
        totals["exports"] += len(exports)
        print(f"  {library.name:45s} exports={len(exports)}")
        for symbol in exports:
            result = demangle(symbol.name)
            if result.kind == "unmangled":
                totals["c"] += 1
                continue
            if result.kind == "undecoded":
                totals["undecoded"] += 1
                if oracle(symbol.name) is not None:
                    buckets["undecoded (oracle succeeds)"] += 1
                continue
            totals["demangled"] += 1
            expected = oracle(symbol.name)
            if expected is None:
                totals["oracle_rejected"] += 1
                continue
            totals["compared"] += 1
            if result.display == expected:
                totals["exact"] += 1
                continue
            bucket = classify(result.display, expected)
            buckets[bucket] += 1
            examples.setdefault(bucket, []).append(
                (symbol.name, result.display, expected)
            )

    print("\n=== totals ===")
    for key in (
        "libraries", "exports", "c", "demangled", "undecoded",
        "compared", "oracle_rejected", "exact",
    ):
        print(f"  {key:18s} {totals[key]}")
    print(f"  {'divergent':18s} {sum(buckets.values())}")

    print("\n=== divergence buckets ===")
    for bucket, count in buckets.most_common():
        print(f"  {count:5d}  {bucket}")
    for bucket, cases in examples.items():
        if bucket == "special-name display format":
            continue
        print(f"\n--- {bucket} (first 2) ---")
        for name, ours, expected in cases[:2]:
            print(f"  mangled : {name}")
            print(f"  ours    : {ours}")
            print(f"  oracle  : {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
