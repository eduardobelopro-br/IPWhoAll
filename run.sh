#!/bin/bash
#
# Execution wrapper for recon.py
# - Creates the venv the first time (if it doesn't exist) and installs dependencies.
# - Automatically activates the venv before running the script.
# - Automatically deactivates the venv on exit (including if interrupted
#   with Ctrl+C).

set -e

VENV_DIR="$HOME/venvs/pentest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_SCRIPT="$SCRIPT_DIR/recon.py"

# Ensures the venv is deactivated on exit, no matter how the script ends
cleanup() {
    if command -v deactivate >/dev/null 2>&1; then
        deactivate
        echo "[*] Venv deactivated."
    fi
}
trap cleanup EXIT

# Creates the venv if it doesn't exist yet
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Venv not found. Creating at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    echo "[*] Installing dependencies (python-whois, requests) ..."
    pip install --quiet --upgrade pip
    pip install --quiet python-whois requests
else
    source "$VENV_DIR/bin/activate"
fi

echo "[*] Venv activated ($VENV_DIR)."
echo ""

python3 "$RECON_SCRIPT"
