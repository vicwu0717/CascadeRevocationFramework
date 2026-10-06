#!/usr/bin/env bash
# =============================================================================
# Script 5: Export Groth16Verifier.sol with real VK constants
# =============================================================================
# Generates contracts/Groth16Verifier.sol directly from the final .zkey.
# This REPLACES the placeholder version that was hand-written earlier.
#
# Run after: 1_compile.sh + 2_setup.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$CIRCUIT_DIR")"

ZKEY_FINAL="$CIRCUIT_DIR/build/certificate_verifier_final.zkey"
OUT_CONTRACT="$PROJECT_DIR/contracts/Groth16Verifier.sol"

if [ ! -f "$ZKEY_FINAL" ]; then
  echo "[ERROR] Proving key not found: $ZKEY_FINAL"
  echo "  Run 1_compile.sh and 2_setup.sh first."
  exit 1
fi

echo "=== Exporting Groth16Verifier.sol ==="
npx snarkjs zkey export solidityverifier \
  "$ZKEY_FINAL" \
  "$OUT_CONTRACT"

echo ""
echo "=== Export complete ==="
echo "  Written: $OUT_CONTRACT"
echo "  File size: $(wc -l < "$OUT_CONTRACT") lines"
echo ""
echo "  NOTE: The exported contract uses function signature:"
echo "    verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[1])"
echo "  which matches IGroth16Verifier.sol — no interface change needed."
echo ""
echo "  Next: recompile the Hardhat project"
echo "    cd $PROJECT_DIR && npx hardhat compile"
