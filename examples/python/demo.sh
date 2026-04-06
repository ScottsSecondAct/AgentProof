#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_SRC="$SCRIPT_DIR/../customer_data_guard.aegis"
POLICY_BIN="$SCRIPT_DIR/../customer_data_guard.aegisc"

echo "=== AutomaGuard Python Example ==="
echo ""

# Compile policy if bytecode is missing
if [[ ! -f "$POLICY_BIN" ]]; then
  echo "Compiling policy..."
  aegisc compile "$POLICY_SRC" -o "$POLICY_BIN"
fi

pip install -q -r "$SCRIPT_DIR/requirements.txt"

echo "--- Safe run (aggregate query, no PII) ---"
python "$SCRIPT_DIR/agent.py" --safe
echo ""

echo "--- Unsafe run (PII exfiltration attempt) ---"
python "$SCRIPT_DIR/agent.py" --unsafe || true
echo ""

if [[ "${1:-}" == "--stress" ]]; then
  echo "--- Stress test (canned event sequences, no LLM required) ---"
  python "$SCRIPT_DIR/stress.py"
fi

echo ""
echo "Done."
