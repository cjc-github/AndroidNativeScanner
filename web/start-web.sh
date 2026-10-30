#!/usr/bin/env bash
# SOInsight Web console launcher - the Linux/macOS twin of start-web.bat.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=""
if command -v python3 >/dev/null 2>&1; then
  PY="python3"
elif command -v python >/dev/null 2>&1; then
  PY="python"
else
  echo "Python 3 was not found on PATH. Install Python 3.10+ and retry." >&2
  exit 1
fi

# Prefer the project virtualenv when it exists: the system Python often lacks
# the project's dependencies, which would break the catalog import.
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
fi

exec "$PY" web/server.py "$@"
