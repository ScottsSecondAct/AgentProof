#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

POLICY_SRC="../customer_data_guard.aegis"
POLICY_BIN="../customer_data_guard.aegisc"

echo "=== AutomaGuard TypeScript Example ==="
echo ""

# Compile policy if bytecode is missing
if [[ ! -f "$POLICY_BIN" ]]; then
  echo "Compiling policy..."
  aegisc compile "$POLICY_SRC" -o "$POLICY_BIN"
fi

npm install -q

echo "--- Safe run (aggregate query, no PII) ---"
npx tsx src/agent.ts --safe
echo ""

echo "--- Unsafe run (PII exfiltration attempt) ---"
npx tsx src/agent.ts --unsafe || true
echo ""

if [[ "${1:-}" == "--stress" ]]; then
  echo "--- Stress test (canned event sequences, no LLM required) ---"
  npx tsx src/stress.ts
fi

echo ""
echo "Done."
