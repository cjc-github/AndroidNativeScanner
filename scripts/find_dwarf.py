"""Locate a real shared library that still carries DWARF debug information.

Most release wheels are stripped, so this downloads several candidates and
reports which ones actually ship `.debug_*` sections. It exists because the
DWARF parser is otherwise only exercised against hand-built debug info: a real
compiler's output is the only way to validate forms the hand-built fixture does
not use.

Usage:
    python scripts/find_dwarf.py
"""

import subprocess
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, "src")

ROOT = Path(__file__).resolve().parent.parent
WHEEL_DIR = ROOT / "tmp_dwarf"
EXTRACT_DIR = ROOT / "tmp_dwarf_sos"

# Wheels that bundle C++ shared libraries.
CANDIDATES = ("pyproj",)


def prepare() -> list[Path]:
    WHEEL_DIR.mkdir(exist_ok=True)
    for wheel in CANDIDATES:
        if list(WHEEL_DIR.glob(f"{wheel}-*.whl")):
            continue
        print("downloading", wheel)
        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "download", "--no-deps",
                "--only-binary=:all:", "--platform", "manylinux2014_x86_64",
                "--python-version", "310", "--implementation", "cp",
                wheel, "-d", str(WHEEL_DIR),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("  failed:", result.stderr.strip().splitlines()[-1:])

    EXTRACT_DIR.mkdir(exist_ok=True)
    for wheel in sorted(WHEEL_DIR.glob("*.whl")):
        target = EXTRACT_DIR / wheel.stem
        if not target.exists():
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(target)
    return sorted(EXTRACT_DIR.rglob("*.so*"))


def libraries() -> Iterator[Path]:
    for library in prepare():
        if "linux-gnu" not in library.name:
            yield library


def main() -> int:
    from soinsight.infrastructure.elf import parse_elf
    from soinsight.infrastructure.dwarf import parse_dwarf

    found = False
    for library in libraries():
        try:
            elf = parse_elf(library)
        except Exception:  # noqa: BLE001
            continue
        debug = [section.name for section in elf.sections if section.name.startswith(".debug")]
        print(f"{library.name}: {library.stat().st_size / 1024 / 1024:.1f} MB  {debug or 'no debug sections'}")
        if not debug:
            continue
        found = True
        info = parse_dwarf(library)
        print(f"  DWARF {info.version}: {len(info.units)} units, {len(info.functions)} subprograms")
        for function in info.functions[:5]:
            print(f"    {function.signature}  [{function.decl_file}:{function.decl_line}]")
    if not found:
        print("\nNo library in this set carries debug information.")
        print("Release wheels are usually stripped; try a distro debug package instead.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
