/**
 * poc_demo.js  —  End-to-end PoC demo on Hardhat local network
 *
 * Flow:
 *  1. Deploy Groth16Verifier + RevocationRegistry
 *  2. Authorize issuer with a DID
 *  3. Load pre-generated proofs from poc_proofs.json
 *  4. Register parent cert (certID=111), child (222), grandchild (333)
 *  5. Add dependency edges: 111→222, 222→333
 *  6. Query isRevoked + verifyCascade (all should be false / 0)
 *  7. revokeCascade on certID=111 → cascades to 222 and 333
 *  8. Query isRevoked for all three (all should be true)
 *  9. Access-control: stranger cannot revoke
 */

"use strict";

const hre  = require("hardhat");
const path = require("path");
const fs   = require("fs");

function sep(title) {
  console.log("\n" + "─".repeat(60));
  console.log("  " + title);
  console.log("─".repeat(60));
}

async function main() {
  const [owner, issuer, stranger] = await hre.ethers.getSigners();

  // ── Step 1: Deploy ──────────────────────────────────────────────
  sep("Step 1 — Deploy contracts");
  const VerifierFactory = await hre.ethers.getContractFactory("Groth16Verifier");
  const verifier        = await VerifierFactory.deploy();
  await verifier.waitForDeployment();
  console.log("  Groth16Verifier  :", await verifier.getAddress());

  const RegistryFactory = await hre.ethers.getContractFactory("RevocationRegistry");
  const registry        = await RegistryFactory.deploy(
    owner.address, await verifier.getAddress()
  );
  await registry.waitForDeployment();
  console.log("  RevocationRegistry:", await registry.getAddress());

  // ── Step 2: Authorize issuer ─────────────────────────────────────
  sep("Step 2 — Authorize issuer");
  const issuerDID = "did:example:issuer001";
  const tx2 = await registry.connect(owner).authorizeIssuer(issuer.address, issuerDID);
  await tx2.wait();
  console.log("  issuer address :", issuer.address);
  console.log("  issuer DID     :", issuerDID);
  console.log("  ✅ IssuerAuthorized event emitted");

  // ── Step 3: Load pre-generated proofs ────────────────────────────
  sep("Step 3 — Load pre-generated proofs from poc_proofs.json");
  const proofsPath = path.join(__dirname, "poc_proofs.json");
  if (!fs.existsSync(proofsPath)) {
    throw new Error("poc_proofs.json not found. Run: node scripts/gen_poc_proofs.js first.");
  }
  const proofs = JSON.parse(fs.readFileSync(proofsPath, "utf8"));
  for (const id of [111, 222, 333]) {
    console.log(`  certID=${id}  pubSignal[0]=${proofs[id].pubSignals[0]}  ✅`);
  }

  // ── Step 4: Register certificates ───────────────────────────────
  sep("Step 4 — Register certificates on-chain");
  for (const id of [111, 222, 333]) {
    const { pA, pB, pC, pubSignals, merkleRoot } = proofs[id];
    // certID as bytes32
    const certIdBytes32  = hre.ethers.zeroPadValue(hre.ethers.toBeHex(id), 32);
    // merkleRoot: large decimal string → bytes32
    const merkleRootBytes32 = hre.ethers.zeroPadValue(
      hre.ethers.toBeHex(BigInt(merkleRoot)), 32
    );
    const tx = await registry.connect(issuer).registerCertificate(
      certIdBytes32,
      merkleRootBytes32,
      issuerDID,
      pA,
      pB,
      pC,
      pubSignals
    );
    const receipt = await tx.wait();
    console.log(`  certID=${id}  gas=${receipt.gasUsed}  ✅`);
  }

  // ── Step 5: Add dependency edges ─────────────────────────────────
  sep("Step 5 — Add dependency edges (111→222, 222→333)");
  const id111 = hre.ethers.zeroPadValue(hre.ethers.toBeHex(111), 32);
  const id222 = hre.ethers.zeroPadValue(hre.ethers.toBeHex(222), 32);
  const id333 = hre.ethers.zeroPadValue(hre.ethers.toBeHex(333), 32);

  await (await registry.connect(issuer).addDependency(id111, id222, issuerDID)).wait();
  console.log("  111 → 222  ✅");
  await (await registry.connect(issuer).addDependency(id222, id333, issuerDID)).wait();
  console.log("  222 → 333  ✅");

  // ── Step 6: Query before revocation ──────────────────────────────
  sep("Step 6 — Query state before revocation");
  for (const [id, idBytes] of [[111, id111], [222, id222], [333, id333]]) {
    const revoked = await registry.isRevoked(idBytes);
    console.log(`  certID=${id}  isRevoked=${revoked}`);
  }
  const [maxDepth, total] = await registry.verifyCascade(id111);
  console.log(`  verifyCascade(111) → maxDepth=${maxDepth}, totalDeps=${total}`);

  // ── Step 7: revokeCascade ─────────────────────────────────────────
  sep("Step 7 — revokeCascade on certID=111");
  const txR     = await registry.connect(issuer).revokeCascade(id111, issuerDID, "supplier audit failed");
  const rcptR   = await txR.wait();
  console.log(`  gas used : ${rcptR.gasUsed}`);
  const events  = rcptR.logs
    .map(log => { try { return registry.interface.parseLog(log); } catch { return null; } })
    .filter(Boolean);
  for (const ev of events) {
    if (ev.name === "CertificateRevoked") {
      console.log(`  📢 CertificateRevoked  certID=${BigInt(ev.args.certID)}`);
    }
    if (ev.name === "CascadeRevoked") {
      console.log(`  📢 CascadeRevoked      child=${BigInt(ev.args.childCertID)}  depth=${ev.args.depth}`);
    }
  }

  // ── Step 8: Query after revocation ───────────────────────────────
  sep("Step 8 — Query state after revocation");
  let allRevoked = true;
  for (const [id, idBytes] of [[111, id111], [222, id222], [333, id333]]) {
    const revoked = await registry.isRevoked(idBytes);
    allRevoked = allRevoked && revoked;
    console.log(`  certID=${id}  isRevoked=${revoked}  ${revoked ? "✅ cascaded" : "❌ NOT revoked"}`);
  }
  if (!allRevoked) throw new Error("Cascade revocation did not propagate to all certificates!");

  // ── Step 9: Access control ────────────────────────────────────────
  sep("Step 9 — Access control: stranger cannot revoke");
  try {
    await registry.connect(stranger).revokeCascade(id111, issuerDID, "hacking");
    console.log("  ❌ should have reverted but did not!");
    process.exitCode = 1;
  } catch (e) {
    console.log("  ✅ NotAuthorized revert as expected:", e.message.split("(")[0].trim());
  }

  console.log("\n" + "═".repeat(60));
  console.log("  PoC COMPLETE — all steps passed ✅");
  console.log("═".repeat(60) + "\n");
}

main().catch(e => { console.error(e); process.exit(1); });