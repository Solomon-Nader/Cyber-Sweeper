#!/usr/bin/env bash
# Cyber Sweeper one-shot setup for Linux / macOS.
# Usage (from the project folder):   bash scripts/setup.sh
set -euo pipefail
echo "== Cyber Sweeper setup =="

PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "Python 3.9+ not found. Debian/Ubuntu: sudo apt install python3 python3-venv python3-tk" >&2
  exit 1
fi
echo "Python  : $("$PY" --version)"

[ -d .venv ] || { "$PY" -m venv .venv; echo "Created .venv"; }
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip --quiet
pip install -e ".[dev]" --quiet
echo "Installed cybersweeper and dependencies"

if command -v nmap >/dev/null; then
  echo "nmap    : found ($(nmap --version | head -1))"
else
  echo "nmap    : NOT found - optional. Debian/Ubuntu: sudo apt install nmap"
fi
python -c 'import tkinter' 2>/dev/null || echo "tkinter : NOT found - needed only for the GUI (sudo apt install python3-tk)"

echo
cybersweeper check
echo
echo "Running the test suite..."
pytest -q
echo
echo "Done. Try:  cybersweeper scan 127.0.0.1 -p common     or     cybersweeper gui"
