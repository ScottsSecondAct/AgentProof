#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_SRC="$SCRIPT_DIR/../customer_data_guard.aegis"
POLICY_BIN="$SCRIPT_DIR/../customer_data_guard.aegisc"

echo "=== AutomaGuard Rust Example ==="
echo ""

# Compile policy if bytecode is missing
if [[ ! -f "$POLICY_BIN" ]]; then
  echo "Compiling policy..."
  aegisc compile "$POLICY_SRC" -o "$POLICY_BIN"
fi

echo "--- Safe run (aggregate query, no PII) ---"
cargo run -q --manifest-path "$SCRIPT_DIR/Cargo.toml" -- --safe
echo ""

echo "--- Unsafe run (PII exfiltration attempt) ---"
cargo run -q --manifest-path "$SCRIPT_DIR/Cargo.toml" -- --unsafe || true
echo ""

if [[ "${1:-}" == "--stress" ]]; then
  echo "--- Stress test (canned event sequences, no LLM required) ---"
  cargo run -q --manifest-path "$SCRIPT_DIR/Cargo.toml" -- --stress
fi

echo ""
echo "Done."
