"""Audit whether every exported function is enumerated.

Compares, per real shared library:
  * the ground-truth export set read independently with pyelftools
    (.dynsym, defined, GLOBAL/WEAK bind, FUNC/IFUNC type);
  * what BasicSymbolsAnalyzer reports;
and explains every difference by category (NOTYPE symbols, symbols only in
.symtab, visibility, duplicates).
"""

import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, "src")

ROOT = Path(__file__).resolve().parent.parent
WHEEL_DIR = ROOT / "tmp_audit"
EXTRACT_DIR = ROOT / "tmp_audit_sos"

WHEELS = ("pyproj",)


def prepare() -> list[Path]:
    WHEEL_DIR.mkdir(exist_ok=True)
    if not list(WHEEL_DIR.glob("*.whl")):
        for wheel in WHEELS:
            subprocess.run(
                [
                    sys.executable, "-m", "pip", "download", "--no-deps",
                    "--only-binary=:all:", "--platform", "manylinux2014_x86_64",
                    "--python-version", "310", "--implementation", "cp",
                    wheel, "-d", str(WHEEL_DIR),
                ],
                check=True, capture_output=True,
            )
    EXTRACT_DIR.mkdir(exist_ok=True)
    found: list[Path] = []
    for wheel in sorted(WHEEL_DIR.glob("*.whl")):
        target = EXTRACT_DIR / wheel.stem
        target.mkdir(exist_ok=True)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(target)
        found.extend(sorted(target.rglob("*.so*")))
    return found


def ground_truth(path: Path) -> set[str]:
    """Independently read .dynsym with pyelftools and collect exported functions."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    names: set[str] = set()
    with open(path, "rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section.name != ".dynsym":
                continue
            for symbol in section.iter_symbols():
                if symbol["st_shndx"] == "SHN_UNDEF":
                    continue
                if symbol["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
                    continue
                if symbol["st_info"]["type"] not in ("STT_FUNC", "STT_GNU_IFUNC"):
                    continue
                if symbol.name:
                    names.add(symbol.name)
    return names


def main() -> int:
    from soinsight.analyzers.symbols import BasicSymbolsAnalyzer
    from soinsight.core.analyzer import AnalysisContext
    from soinsight.core.models import AnalysisTarget
    from soinsight.infrastructure.config import RuntimeConfig
    from soinsight.infrastructure.elf import parse_elf

    totals: Counter[str] = Counter()
    for library in prepare():
        if "linux-gnu" in library.name:
            continue
        try:
            elf = parse_elf(library)
        except Exception:  # noqa: BLE001
            continue

        expected = ground_truth(library)
        dynsym_functions = {
            symbol.name
            for symbol in elf.symbols_from(".dynsym")
            if symbol.is_exported and symbol.is_function
        }

        target = AnalysisTarget(
            path=library, real_path=library.resolve(), name=library.name,
            size=library.stat().st_size, sha256="audit",
        )
        data = BasicSymbolsAnalyzer().analyze(
            target, AnalysisContext("run", target, RuntimeConfig())
        ).data
        reported = {record["name"] for record in data["functions"]}

        # Categories of difference.
        notype_exported = {
            symbol.name
            for symbol in elf.symbols_from(".dynsym")
            if symbol.is_exported
            and symbol.type == "NOTYPE"
            and symbol.is_defined
        }
        symtab_only = reported - dynsym_functions
        hidden = {
            symbol.name
            for symbol in elf.symbols_from(".dynsym")
            if symbol.is_exported and symbol.is_function
            and symbol.visibility == "HIDDEN"
        }

        missing = expected - reported
        extra = reported - expected

        totals["libraries"] += 1
        totals["expected"] += len(expected)
        totals["reported"] += len(reported)
        totals["missing"] += len(missing)
        totals["extra"] += len(extra)
        totals["notype_exported"] += len(notype_exported)
        totals["symtab_only"] += len(symtab_only)
        totals["hidden"] += len(hidden)

        print(f"{library.name}")
        print(f"  ground truth (pyelftools .dynsym) : {len(expected)}")
        print(f"  BasicSymbolsAnalyzer reports     : {len(reported)}")
        print(f"  missing from report              : {len(missing)}")
        print(f"  extra in report                  : {len(extra)}")
        print(f"    of which NOTYPE exports        : {len(notype_exported)}")
        print(f"    of which .symtab-only          : {len(symtab_only)}")
        print(f"    of which HIDDEN visibility     : {len(hidden)}")
        for name in sorted(missing)[:5]:
            print(f"      missing: {name}")
        for name in sorted(extra)[:5]:
            print(f"      extra  : {name}")

    print("\n=== totals ===")
    for key in (
        "libraries", "expected", "reported", "missing", "extra",
        "notype_exported", "symtab_only", "hidden",
    ):
        print(f"  {key:20s} {totals[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
