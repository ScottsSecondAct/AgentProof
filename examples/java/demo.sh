#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

POLICY_SRC="../customer_data_guard.aegis"
POLICY_BIN="../customer_data_guard.aegisc"

echo "=== AutomaGuard Java Example ==="
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

# Build SDK and example.
(cd ../../automaguard-java && mvn -q install -DskipTests)
mvn -q package -DskipTests

echo "--- Safe run (aggregate query, no PII) ---"
java -jar target/customer-data-assistant.jar --safe
echo ""

echo "--- Unsafe run (PII exfiltration attempt) ---"
java -jar target/customer-data-assistant.jar --unsafe || true
echo ""

echo "Done. Check audit log: /tmp/automaguard_audit.jsonl"
