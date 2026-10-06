/**
 * deploy.js — Deployment script for the RevocationRegistry project.
 *
 * Deployment order:
 *   1. Deploy Groth16Verifier  (pure verifier, no constructor args)
 *   2. Deploy RevocationRegistry(owner, verifierAddress)
 *   3. (Optional) Authorize initial issuers
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network sepolia
 *
 * Environment variables (set in .env):
 *   SEPOLIA_RPC_URL        — RPC endpoint (e.g. Alchemy / Infura)
 *   DEPLOYER_PRIVATE_KEY   — 0x-prefixed private key of the deployer
 *   OWNER_ADDRESS          — address that will own RevocationRegistry
 *                            (defaults to deployer if not set)
 */

const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log(
    "Account balance:",
    ethers.formatEther(await ethers.provider.getBalance(deployer.address)),
    "ETH"
  );

  // ── 1. Deploy Groth16Verifier ─────────────────────────────────────
  console.log("\n[1/2] Deploying Groth16Verifier...");
  const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Groth16Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("  Groth16Verifier deployed to:", verifierAddress);

  // ── 2. Deploy RevocationRegistry ─────────────────────────────────
  console.log("\n[2/2] Deploying RevocationRegistry...");
  const ownerAddress = process.env.OWNER_ADDRESS || deployer.address;
  const RevocationRegistry = await ethers.getContractFactory("RevocationRegistry");
  const registry = await RevocationRegistry.deploy(ownerAddress, verifierAddress);
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log("  RevocationRegistry deployed to:", registryAddress);
  console.log("  Owner set to:", ownerAddress);
  console.log("  Verifier set to:", verifierAddress);

  // ── 3. (Optional) Authorize a test issuer ────────────────────────
  // Uncomment and fill in to pre-authorize an issuer at deployment time:
  //
  // const testIssuerAddress = "0xYourIssuerAddressHere";
  // const testIssuerDID     = "did:example:supplychain-issuer-001";
  // console.log("\n[Optional] Authorizing test issuer...");
  // const tx = await registry.authorizeIssuer(testIssuerAddress, testIssuerDID);
  // await tx.wait();
  // console.log("  Authorized:", testIssuerAddress, "→", testIssuerDID);

  // ── Summary ───────────────────────────────────────────────────────
  console.log("\n═══════════════════════════════════════════════════════");
  console.log("Deployment complete.");
  console.log("  Groth16Verifier  :", verifierAddress);
  console.log("  RevocationRegistry:", registryAddress);
  console.log("═══════════════════════════════════════════════════════");
  console.log("\nNext steps:");
  console.log("  1. Replace VK_* constants in Groth16Verifier.sol with your vk.json values.");
  console.log("  2. Redeploy Groth16Verifier and call registry.setVerifier(newAddress).");
  console.log("  3. Call registry.authorizeIssuer(addr, did) for each issuer.");
  console.log("  4. Verify on Etherscan:");
  console.log("     npx hardhat verify --network sepolia", verifierAddress);
  console.log("     npx hardhat verify --network sepolia", registryAddress, ownerAddress, verifierAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});