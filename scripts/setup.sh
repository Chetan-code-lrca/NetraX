#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3.12+ is required. Install Python and retry." >&2
  exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit("NetraX requires Python 3.12 or newer.")
print(f"Using Python {sys.version.split()[0]}")
PY

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Node.js 20+ and npm are required for the dashboard." >&2
  exit 1
fi

if [ ! -d .venv ]; then
  "$PYTHON_BIN" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install cicflowmeter

mkdir -p model-artifacts
npm --prefix frontend ci

echo
echo "NetraX setup complete."
echo "Start the API:       source .venv/bin/activate && python -m uvicorn api.main:app --host 127.0.0.1 --port 8000"
echo "Start the dashboard: cd frontend && npm run dev"
echo "Before model-based analysis, place the trusted files in model-artifacts/."
echo "See model-artifacts/README.md and docs/INTERVIEW_GUIDE.md."
