#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
DIST_DIR="${DIST_DIR:-${ROOT_DIR}/dist}"
INSTALL=false

usage() {
    cat <<'USAGE'
Usage: scripts/build_cli.sh [--install] [--help]

Build the SOInsight V2 CLI wheel into dist/ and verify that the wheel contains
both the soinsight package and the `soinsight` console entry point.

Options:
  --install  Install/reinstall the generated wheel into the current Python environment.
  --help     Show this help.

Environment variables:
  PYTHON_BIN  Python executable to use (default: python3)
  DIST_DIR    Wheel output directory (default: <repo>/dist)

Examples:
  ./scripts/build_cli.sh
  ./scripts/build_cli.sh --install
  PYTHON_BIN=python3.10 ./scripts/build_cli.sh
USAGE
}

while (($#)); do
    case "$1" in
        --install)
            INSTALL=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

command -v "${PYTHON_BIN}" >/dev/null 2>&1 || {
    echo "Python executable not found: ${PYTHON_BIN}" >&2
    exit 1
}

cd "${ROOT_DIR}"
mkdir -p "${DIST_DIR}"
rm -rf build src/soinsight.egg-info
rm -f "${DIST_DIR}"/soinsight-*.whl

echo "==> Building SOInsight CLI wheel"
"${PYTHON_BIN}" -m pip wheel \
    . \
    --no-deps \
    --no-build-isolation \
    --wheel-dir "${DIST_DIR}"

WHEEL_PATH="$(find "${DIST_DIR}" -maxdepth 1 -type f -name 'soinsight-*.whl' -print | sort | tail -n 1)"
if [[ -z "${WHEEL_PATH}" ]]; then
    echo "Build completed without producing a soinsight wheel." >&2
    exit 1
fi

echo "==> Verifying wheel metadata and console entry point"
"${PYTHON_BIN}" - "${WHEEL_PATH}" <<'PY'
from pathlib import Path
import sys
import zipfile

wheel = Path(sys.argv[1])
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    if "soinsight/cli/main.py" not in names:
        raise SystemExit("Wheel does not contain soinsight/cli/main.py")

    entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
    if len(entry_points) != 1:
        raise SystemExit("Wheel does not contain exactly one entry_points.txt")

    content = archive.read(entry_points[0]).decode("utf-8")
    expected = "soinsight = soinsight.cli.main:main"
    if expected not in content:
        raise SystemExit(f"Missing console entry point: {expected}")

print(f"Verified: {wheel.name}")
PY

echo "==> Running source-tree CLI smoke test"
PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "${PYTHON_BIN}" -m soinsight --version

if [[ "${INSTALL}" == true ]]; then
    echo "==> Installing ${WHEEL_PATH}"
    "${PYTHON_BIN}" -m pip install --force-reinstall "${WHEEL_PATH}"
    echo "==> Installed CLI"
    if command -v soinsight >/dev/null 2>&1; then
        soinsight --version
    else
        echo "Wheel installed, but 'soinsight' is not on PATH." >&2
        echo "Try: ${PYTHON_BIN} -m soinsight --version" >&2
    fi
fi

echo
echo "SOInsight CLI wheel created: ${WHEEL_PATH}"
echo "Install it with:"
echo "  ${PYTHON_BIN} -m pip install --force-reinstall '${WHEEL_PATH}'"
echo "Then run:"
echo "  soinsight --help"
