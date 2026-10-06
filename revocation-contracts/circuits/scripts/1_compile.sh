#!/usr/bin/env bash
set -eu

BUILD_DIR="./build"

echo "=== Compiling certificate_verifier.circom ==="
mkdir -p "$BUILD_DIR"

circom certificate_verifier.circom --r1cs --wasm --sym --output "$BUILD_DIR" -l "./node_modules"

echo "=== Compilation complete ==="
npx snarkjs r1cs info "$BUILD_DIR/certificate_verifier.r1cs"