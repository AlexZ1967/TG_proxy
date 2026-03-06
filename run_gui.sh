#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${TG_PROXY_GUI_PYTHON:-}" ]]; then
  PYTHON_BIN="$TG_PROXY_GUI_PYTHON"
elif /usr/bin/python3 -c "import gi" >/dev/null 2>&1; then
  PYTHON_BIN="/usr/bin/python3"
elif [[ -n "${TG_PROXY_PYTHON:-}" ]] && "$TG_PROXY_PYTHON" -c "import gi" >/dev/null 2>&1; then
  PYTHON_BIN="$TG_PROXY_PYTHON"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import gi" >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1 && python -c "import gi" >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "No Python interpreter with PyGObject found. Set TG_PROXY_GUI_PYTHON or install python3-gi." >&2
  exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/tg_ws_gui.py" "$@"
