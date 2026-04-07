#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

POLICY_SRC="../customer_data_guard.aegis"
POLICY_BIN="../customer_data_guard.aegisc"

echo "=== AutomaGuard .NET Example ==="
echo ""

# Compile policy bytecode if it does not already exist.
if [[ ! -f "$POLICY_BIN" ]]; then
  echo "Compiling policy..."
  aegisc compile "$POLICY_SRC" -o "$POLICY_BIN"
fi

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "Error: OPENAI_API_KEY is not set." >&2
  exit 1
fi

dotnet restore -q

echo "--- Safe run (aggregate query, no PII) ---"
dotnet run -- --safe
echo ""

echo "--- Unsafe run (PII exfiltration attempt) ---"
dotnet run -- --unsafe || true
echo ""

echo "Done. Check audit log: /tmp/automaguard_audit.jsonl"
