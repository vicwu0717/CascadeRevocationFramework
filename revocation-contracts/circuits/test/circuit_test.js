/**
 * circuits/test/circuit_test.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for CertificateVerifier circuit (pure JS, no Hardhat needed).
 *
 * Tests:
 *   1. Valid witness computes correctly (proof passes local verification)
 *   2. Public signal[0] equals certID
 *   3. Different certIDs produce different public signals
 *   4. Wrong merkleRoot is rejected
 *   5. Tampered attribute is rejected
 *   6. Wrong path element is rejected
 *   7. Wrong issuerSecret is rejected
 *
 * Run:
 *   cd circuits && node test/circuit_test.js
 * ─────────────────────────────────────────────────────────────────────────────
 */
"use strict";

const path    = require("path");
const assert  = require("assert");
const fs      = require("fs");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const BUILD   = path.join(__dirname, "../build");
const WASM    = path.join(BUILD, "certificate_verifier_js/certificate_verifier.wasm");
const ZKEY    = path.join(BUILD, "zkey_final.zkey");
const VK_PATH = path.join(BUILD, "vk.json");

// ── Helpers ───────────────────────────────────────────────────────────────────

let poseidon;

async function init() {
  poseidon = await buildPoseidon();
}

function poseidonHash(values) {
  return poseidon.F.toObject(poseidon(values));
}

/**
 * buildInputs({ certID, attributes, issuerSecret })
 * Constructs a valid input object with correct Merkle path.
 */
function buildInputs({ certID, attributes = [1n,2n,3n,4n,5n], issuerSecret = 0xDEADBEEFn } = {}) {
  const leaf = poseidonHash([certID, ...attributes, issuerSecret]);

  const pathElements = [];
  const pathIndices  = [];
  let current = leaf;

  for (let i = 0; i < 20; i++) {
    pathElements.push("0");
    pathIndices.push("0");
    current = poseidonHash([current, 0n]);
  }

  return {
    certID:       certID.toString(),
    attributes:   attributes.map(a => a.toString()),
    issuerSecret: issuerSecret.toString(),
    merkleRoot:   current.toString(),
    pathElements,
    pathIndices,
  };
}

/**
 * proveAndVerify(inputs) → { ok: boolean, publicSignals }
 * Uses groth16.fullProve (handles witness internally).
 * Returns ok=false if witness generation or verification fails.
 */
async function proveAndVerify(inputs) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    return { ok, publicSignals };
  } catch (_err) {
    return { ok: false, publicSignals: null };
  }
}

// ── Test runner ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✔  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✘  ${name}`);
    console.error(`       ${err.message}`);
    failed++;
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

(async () => {
  // Check build artifacts exist
  for (const [label, p] of [["WASM", WASM], ["zkey", ZKEY], ["vk.json", VK_PATH]]) {
    if (!fs.existsSync(p)) {
      console.error(`\n  [SKIP] Build artifact not found: ${label} (${p})`);
      console.error("  Run 'npm run compile && npm run setup' first.\n");
      process.exit(0);
    }
  }

  await init();

  console.log("\n  CertificateVerifier circuit tests\n");

  // ── Test 1: Happy path ─────────────────────────────────────────────────────
  await test("valid inputs: proof generates and verifies", async () => {
    const inputs = buildInputs({ certID: 123456n });
    const { ok, publicSignals } = await proveAndVerify(inputs);
    assert.strictEqual(ok, true, "Proof should verify");
    assert.strictEqual(publicSignals[0], "123456", "Public signal should be certID");
  });

  // ── Test 2: Public signal == certID ───────────────────────────────────────
  await test("public signal[0] equals the certID input", async () => {
    const inputs = buildInputs({ certID: 999888777n });
    const { ok, publicSignals } = await proveAndVerify(inputs);
    assert.strictEqual(ok, true);
    assert.strictEqual(publicSignals[0], "999888777");
  });

  // ── Test 3: Different certID → different public signal ─────────────────────
  await test("two different certIDs produce different public signals", async () => {
    const r1 = await proveAndVerify(buildInputs({ certID: 1n }));
    const r2 = await proveAndVerify(buildInputs({ certID: 2n }));
    assert.ok(r1.ok && r2.ok);
    assert.notStrictEqual(r1.publicSignals[0], r2.publicSignals[0]);
  });

  // ── Test 4: Wrong merkleRoot → constraint violation ────────────────────────
  await test("wrong merkleRoot is rejected by constraint", async () => {
    const inputs = buildInputs({ certID: 111n });
    inputs.merkleRoot = "12345678901234567890";  // tampered root
    const { ok } = await proveAndVerify(inputs);
    assert.strictEqual(ok, false, "Tampered root should fail");
  });

  // ── Test 5: Tampered attribute → leaf hash changes → root mismatch ─────────
  await test("tampered attribute invalidates the proof", async () => {
    const inputs = buildInputs({ certID: 222n });
    inputs.attributes[0] = "99";  // was "1"
    const { ok } = await proveAndVerify(inputs);
    assert.strictEqual(ok, false, "Tampered attribute should fail");
  });

  // ── Test 6: Wrong path element → root mismatch ────────────────────────────
  await test("wrong pathElements invalidates the proof", async () => {
    const inputs = buildInputs({ certID: 333n });
    inputs.pathElements[0] = "99999999";  // tampered sibling
    const { ok } = await proveAndVerify(inputs);
    assert.strictEqual(ok, false, "Tampered path element should fail");
  });

  // ── Test 7: Wrong issuerSecret → different leaf → root mismatch ────────────
  await test("wrong issuerSecret invalidates the proof", async () => {
    const inputs = buildInputs({ certID: 444n, issuerSecret: 0xDEADBEEFn });
    inputs.issuerSecret = "1";  // wrong secret
    const { ok } = await proveAndVerify(inputs);
    assert.strictEqual(ok, false, "Wrong issuerSecret should fail");
  });

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log(`\n  ${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
})();