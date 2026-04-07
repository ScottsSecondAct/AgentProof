#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_SRC="$SCRIPT_DIR/../customer_data_guard.aegis"
POLICY_BIN="$SCRIPT_DIR/../customer_data_guard.aegisc"

echo "=== AutomaGuard Go Example ==="
echo ""

# Compile policy if bytecode is missing
if [[ ! -f "$POLICY_BIN" ]]; then
  echo "Compiling policy..."
  aegisc compile "$POLICY_SRC" -o "$POLICY_BIN"
fi

BIN="$SCRIPT_DIR/customer_agent"
go build -o "$BIN" "$SCRIPT_DIR"

echo "--- Safe run (aggregate query, no PII) ---"
"$BIN" --safe
echo ""

echo "--- Unsafe run (PII exfiltration attempt) ---"
"$BIN" --unsafe || true
echo ""

if [[ "${1:-}" == "--stress" ]]; then
  echo "--- Stress test (canned event sequences, no LLM required) ---"
  "$BIN" --stress
fi

rm -f "$BIN"
echo ""
echo "Done."
