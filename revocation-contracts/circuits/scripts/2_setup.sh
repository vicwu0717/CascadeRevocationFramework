#!/usr/bin/env bash
# =============================================================================
# Script 2: Groth16 Trusted Setup (Powers of Tau + Phase 2)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE<sup>0</sup>}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUIT_DIR/build"

PTAU_FILE="$BUILD_DIR/pot15_final.ptau"
ZKEY_0="$BUILD_DIR/certificate_verifier_0000.zkey"
ZKEY_FINAL="$BUILD_DIR/certificate_verifier_final.zkey"
VK_FILE="$BUILD_DIR/vk.json"

mkdir -p "$BUILD_DIR"

# Phase 1: Powers of Tau
if [ ! -f "$PTAU_FILE" ]; then

  DOWNLOAD_OK=0
  for URL in \
    "https://storage.googleapis.com/zkevm/ptau/hermez-raw-15" \
    "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau" \
    "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau"; do

    echo "  Trying: $URL"
    curl -fL --max-time 60 --retry 1 -o "$PTAU_FILE" "$URL" 2>/dev/null && {
      FILE_SIZE=$(wc -c < "$PTAU_FILE")
      if [ "$FILE_SIZE" -gt 1000000 ]; then
        echo "  Download OK ($(du -sh "$PTAU_FILE" | cut -f1))"
        DOWNLOAD_OK=1
        break
      else
        echo "  Only ${FILE_SIZE} bytes -- invalid. Removing."
        rm -f "$PTAU_FILE"
      fi
    } || rm -f "$PTAU_FILE"
  doneif [ "$DOWNLOAD_OK" -eq 0 ]; then
    echo ""
    echo "=== [1/4] Download unavailable -- generating Powers of Tau locally ==="
    echo "  (Safe for dev/PoC. Circuit has ~5200 constraints; pot14 = 2^14 = 16384 >= 5200)"
    echo ""

    POT_RAW="$BUILD_DIR/pot14_0000.ptau"
    POT_CONTRIB="$BUILD_DIR/pot14_0001.ptau"

    echo "  Step 1/3 -- new ceremony..."
    npx snarkjs powersoftau new bn128 14 "$POT_RAW" -v

    echo ""
    echo "  Step 2/3 -- contributing randomness..."
    ENTROPY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    echo "$ENTROPY" | npx snarkjs powersoftau contribute \
      "$POT_RAW" "$POT_CONTRIB" \
      --name="Dev PoC contribution $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -e="$ENTROPY"

    echo ""
    echo "  Step 3/3 -- preparing phase2 (may take 2-5 minutes)..."
    npx snarkjs powersoftau prepare phase2 "$POT_CONTRIB" "$PTAU_FILE" -v

    rm -f "$POT_RAW" "$POT_CONTRIB"
    echo ""
    echo "  Generated: $(du -sh "$PTAU_FILE" | cut -f1)"
  fi

else
  echo "=== [1/4] pot15_final.ptau already exists ($(du -sh "$PTAU_FILE" | cut -f1)), skipping ==="
fi

# Phase 2: Circuit-specific setup
echo ""
echo "=== [2/4] Running Phase 2 setup ==="
npx snarkjs groth16 setup \
  "$BUILD_DIR/certificate_verifier.r1cs" \
  "$PTAU_FILE" \
  "$ZKEY_0"

# Phase 2 contribution
echo ""
echo "=== [3/4] Adding random contribution ==="
RANDOM_ENTROPY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
npx snarkjs zkey contribute \
  "$ZKEY_0" \
  "$ZKEY_FINAL" \
  --name="Automated contribution $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -e="$RANDOM_ENTROPY"

# Export verification key
echo ""
echo "=== [4/4] Exporting verification key ==="
npx snarkjs zkey export verificationkey \
  "$ZKEY_FINAL" \
  "$VK_FILE"

echo ""
echo "=== Trusted Setup complete ==="
echo "  Proving key : $ZKEY_FINAL"
echo "  VK JSON     : $VK_FILE"
echo ""
echo "  Next: bash scripts/5_export_verifier.sh"
