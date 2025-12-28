#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/setup_wsl.sh [options]

Prepare a WSL/Linux environment for PyCIPSim by creating a virtual
environment, installing dependencies, running a smoke test, and
optionally launching the web UI.

Options:
  --with-pycomm3   Install optional pycomm3 extras for hardware access.
  --skip-tests     Skip running the pytest suite after installation.
  --start-web      Launch the FastAPI web UI once setup succeeds.
  --port <port>    Port to use when starting the web UI (default: 8000).
  -h, --help       Show this help message.

Environment overrides:
  PYTHON_BIN  Python executable to use (default: python3)
  VENV_PATH   Virtual environment directory (default: .venv in repo root)

Examples:
  bash scripts/setup_wsl.sh
  bash scripts/setup_wsl.sh --with-pycomm3 --start-web --port 8080
  PYTHON_BIN=python3.11 bash scripts/setup_wsl.sh --skip-tests
EOF
}

WITH_PYCOMM3=false
RUN_TESTS=true
START_WEB=false
PORT="${PORT:-8000}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="${VENV_PATH:-$ROOT_DIR/.venv}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-pycomm3)
      WITH_PYCOMM3=true
      ;;
    --skip-tests)
      RUN_TESTS=false
      ;;
    --start-web)
      START_WEB=true
      ;;
    --port)
      PORT="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script targets Linux/WSL. Detected: $(uname -s)" >&2
  exit 1
fi

if grep -qi microsoft /proc/version 2>/dev/null; then
  echo "WSL environment detected."
else
  echo "Non-WSL Linux detected; continuing with setup."
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable '$PYTHON_BIN' not found. Install python3 and python3-venv (e.g., sudo apt-get install python3 python3-venv)." >&2
  exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 10):
    sys.exit("Python 3.10+ is required for PyCIPSim.")
PY

if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
  echo "python3-venv is missing. Install it with: sudo apt-get install python3-venv" >&2
  exit 1
fi

cd "$ROOT_DIR"

if [[ ! -d "$VENV_PATH" ]]; then
  echo "Creating virtual environment at $VENV_PATH"
  "$PYTHON_BIN" -m venv "$VENV_PATH"
else
  echo "Reusing existing virtual environment at $VENV_PATH"
fi

# shellcheck source=/dev/null
source "$VENV_PATH/bin/activate"

echo "Upgrading pip and wheel..."
python -m pip install --upgrade pip wheel >/dev/null

EXTRAS="dev"
if $WITH_PYCOMM3; then
  EXTRAS="dev,pycomm3"
fi

echo "Installing PyCIPSim with extras: [$EXTRAS]"
python -m pip install -e ".[${EXTRAS}]"

echo "Running CLI smoke checks..."
pycipsim --help >/dev/null
pycipsim list-profiles >/dev/null

if $RUN_TESTS; then
  echo "Executing pytest suite..."
  python -m pytest -q
else
  echo "Skipping tests per --skip-tests."
fi

if $START_WEB; then
  echo "Starting FastAPI web UI at http://localhost:${PORT} (Ctrl+C to stop)..."
  exec pycipsim web --host 0.0.0.0 --port "$PORT"
fi

cat <<EOF
Setup complete.
- Activate your environment: source "$VENV_PATH/bin/activate"
- Run the CLI: pycipsim run --scenario <path> --report <path>
- Launch the web UI: pycipsim web --host 0.0.0.0 --port ${PORT}
EOF
