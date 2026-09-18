#!/usr/bin/env bash
# BreachLabs demo runner for Git Bash / MSYS2 on Windows.
# Runs a full sandboxed assessment of the vulnerable demo target, streams
# progress AND the final report to stdout, and saves everything to Report.md.
#
# Usage:
#   ./run_demo.sh            # uses .venv, port 5005
#   ./run_demo.sh 5006       # custom target port
set -euo pipefail

cd "$(dirname "$0")"

PORT="${1:-5005}"
PY=".venv/Scripts/python.exe"
if [ ! -x "$PY" ]; then
  PY=".venv/bin/python"
fi

echo "=== BreachLabs demo (Report.md) ==="
"$PY" -m pip install -q -e ".[dev]" flask
"$PY" -m breachlabs.demo_runner --port "$PORT" 2>&1 | tee Report.md
echo ""
echo "Done. Full output saved to Report.md"
