#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${TG_PROXY_PYTHON:-}" ]]; then
  PYTHON_BIN="$TG_PROXY_PYTHON"
elif [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "No Python interpreter found. Set TG_PROXY_PYTHON or create .venv." >&2
  exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/tg_ws_proxy.py" "$@"
