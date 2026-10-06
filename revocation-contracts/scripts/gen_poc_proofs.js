/**
 * gen_poc_proofs.js  —  預生成 certID=111/222/333 的 Groth16 calldata
 * 兩步驟：
 *   1. generate_witness.js (.wasm + input.json → .wtns)
 *   2. snarkjs.groth16.prove (.zkey + .wtns → proof, publicSignals)
 *
 * 執行方式: node scripts/gen_poc_proofs.js
 * 輸出: scripts/poc_proofs.json
 */
"use strict";

const snarkjs  = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { execFileSync } = require("child_process");
const path = require("path");
const fs   = require("fs");
const os   = require("os");

const BUILD   = path.join(__dirname, "../circuits/build");
const WASM    = path.join(BUILD, "certificate_verifier_js/certificate_verifier.wasm");
const GEN_WIT = path.join(BUILD, "certificate_verifier_js/generate_witness.js");
const ZKEY    = path.join(BUILD, "zkey_final.zkey");
const TMP     = os.tmpdir();

function poseidonHash(poseidon, values) {
  return poseidon.F.toObject(poseidon(values));
}
function buildMerkleTree(poseidon, leaf, levels = 20) {
  const pathElements = [], pathIndices = [];
  let current = leaf;
  for (let i = 0; i < levels; i++) {
    pathElements.push("0"); pathIndices.push("0");
    current = poseidonHash(poseidon, [current, 0n]);
  }
  return { root: current.toString(), pathElements, pathIndices };
}
async function buildInput(poseidon, certId) {
  const certID = BigInt(certId);
  const attributes   = [1n, 2n, 3n, 4n, 5n];
  const issuerSecret = 0xDEADBEEFn;
  const leaf = poseidonHash(poseidon, [certID, ...attributes, issuerSecret]);
  const { root, pathElements, pathIndices } = buildMerkleTree(poseidon, leaf);
  return {
    certID: certID.toString(), attributes: attributes.map(a => a.toString()),
    issuerSecret: issuerSecret.toString(), merkleRoot: root, pathElements, pathIndices,
  };
}

(async () => {
  const poseidon = await buildPoseidon();
  const result = {};

  for (const id of [111, 222, 333]) {
    process.stdout.write(`certID=${id}: building input ... `);
    const input    = await buildInput(poseidon, id);
    const inPath   = path.join(TMP, `input_${id}.json`);
    const wtnsPath = path.join(TMP, `witness_${id}.wtns`);
    fs.writeFileSync(inPath, JSON.stringify(input));

    // Step 1: generate witness (no WASM worker thread, runs synchronously)
    process.stdout.write("witness ... ");
    execFileSync(process.execPath, [GEN_WIT, WASM, inPath, wtnsPath], { stdio: "pipe" });

    // Step 2: prove (reads .wtns, singleThread avoids Worker CodeRange OOM)
    process.stdout.write("proof ... ");
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY, wtnsPath, null, {singleThread: true});
    const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
    const parsed = JSON.parse("[" + cd + "]");
    result[id] = { pA: parsed[0], pB: parsed[1], pC: parsed[2], pubSignals: parsed[3],
                   merkleRoot: input.merkleRoot };
    console.log("✅  pubSignal[0]=" + publicSignals[0]);

    // cleanup tmp
    fs.unlinkSync(inPath); fs.unlinkSync(wtnsPath);
  }

  const outPath = path.join(__dirname, "poc_proofs.json");
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.log("\nSaved to:", outPath);
})().catch(e => { console.error(e); process.exit(1); });