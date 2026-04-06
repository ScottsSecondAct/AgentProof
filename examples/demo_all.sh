#!/usr/bin/env bash
# Run all SDK examples against the shared CustomerDataGuard policy.
# Each SDK demonstrates the same safe and unsafe scenarios.
set -euo pipefail
EXAMPLES_DIR="$(cd "$(dirname "$0")" && pwd)"

# Compile the shared policy once
if [[ ! -f "$EXAMPLES_DIR/customer_data_guard.aegisc" ]]; then
  echo "Compiling shared policy..."
  aegisc compile "$EXAMPLES_DIR/customer_data_guard.aegis" \
         -o "$EXAMPLES_DIR/customer_data_guard.aegisc"
fi

SDKS=(python rust typescript)

# Add other SDKs when their examples exist
[[ -f "$EXAMPLES_DIR/dotnet/demo.sh"     ]] && SDKS+=(dotnet)
[[ -f "$EXAMPLES_DIR/java/demo.sh"       ]] && SDKS+=(java)
[[ -f "$EXAMPLES_DIR/go/demo.sh"         ]] && SDKS+=(go)


for sdk in "${SDKS[@]}"; do
  echo ""
  echo "════════════════════════════════════════"
  echo " SDK: $sdk"
  echo "════════════════════════════════════════"
  bash "$EXAMPLES_DIR/$sdk/demo.sh"
done

echo ""
echo "All examples complete."
