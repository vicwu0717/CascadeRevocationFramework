/**
 * RevocationRegistry.test.js
 *
 * Hardhat / Mocha / Chai test suite for RevocationRegistry.sol.
 * Uses a MockVerifier so tests do NOT require real zk-SNARK proofs.
 *
 * Test groups
 * ──────────────────────────────────────────────────────────────────
 *  1. Deployment
 *  2. authorizeIssuer / revokeIssuerAuthorization
 *  3. onlyAuthorized modifier (boundary cases)
 *  4. registerCertificate  (happy path + all revert paths)
 *  5. revokeCertificate    (happy path + all revert paths)
 *  6. revokeCascade        (linear chain, branching, edge cases)
 *  7. addDependency
 *  8. setVerifier / pause / unpause  (admin functions)
 *  9. view functions: isRevoked, verifyCertificate, verifyCascade
 *
 * Run:  npx hardhat test
 */

const { ethers }  = require("hardhat");
const { expect }  = require("chai");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

// ─── Shared helpers ──────────────────────────────────────────────────────────

/** Zero-value proof params accepted by MockVerifier (values don't matter). */
const ZERO_PROOF = {
  pA: [0n, 0n],
  pB: [[0n, 0n], [0n, 0n]],
  pC: [0n, 0n],
};

/**
 * Build a certID (bytes32) from an arbitrary integer seed and derive
 * the matching _pubSignals[0] = uint256(certID).
 */
function makeCert(seed) {
  const certID = ethers.zeroPadValue(ethers.toBeHex(seed), 32);
  const pubSig  = [BigInt(certID)];
  return { certID, pubSig };
}

const MERKLE_ROOT = ethers.zeroPadValue("0x01", 32);
const DID_A       = "did:example:issuer-A";
const DID_B       = "did:example:issuer-B";

// ─── Base fixture: deploy MockVerifier + Registry ────────────────────────────

async function deployFixture() {
  const [owner, issuerA, issuerB, stranger] = await ethers.getSigners();

  const MockVerifier = await ethers.getContractFactory("MockVerifier");
  const verifier = await MockVerifier.deploy(true); // starts passing
  await verifier.waitForDeployment();

  const Registry = await ethers.getContractFactory("RevocationRegistry");
  const registry = await Registry.deploy(owner.address, await verifier.getAddress());
  await registry.waitForDeployment();

  return { registry, verifier, owner, issuerA, issuerB, stranger };
}

// ─── Fixture: registry with issuerA already authorized ───────────────────────

async function authorizedFixture() {
  const base = await deployFixture();
  const { registry, owner, issuerA } = base;
  await registry.connect(owner).authorizeIssuer(issuerA.address, DID_A);
  return base;
}

// ─── Fixture: one cert registered by issuerA ─────────────────────────────────

async function oneCertFixture() {
  const base = await authorizedFixture();
  const { registry, issuerA } = base;
  const { certID, pubSig } = makeCert(1);
  await registry.connect(issuerA).registerCertificate(
    certID, MERKLE_ROOT, DID_A,
    ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
  );
  return { ...base, certID, pubSig };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Deployment
// ─────────────────────────────────────────────────────────────────────────────

describe("1. Deployment", function () {
  it("sets the correct owner", async function () {
    const { registry, owner } = await loadFixture(deployFixture);
    expect(await registry.owner()).to.equal(owner.address);
  });

  it("sets the correct verifier address", async function () {
    const { registry, verifier } = await loadFixture(deployFixture);
    expect(await registry.verifier()).to.equal(await verifier.getAddress());
  });

  it("reverts with ZeroAddress when owner is zero", async function () {
    const { verifier } = await loadFixture(deployFixture);
    const Registry = await ethers.getContractFactory("RevocationRegistry");
    await expect(
      Registry.deploy(ethers.ZeroAddress, await verifier.getAddress())
    ).to.be.revertedWithCustomError(Registry, "ZeroAddress");
  });

  it("reverts with ZeroAddress when verifier is zero", async function () {
    const [owner] = await ethers.getSigners();
    const Registry = await ethers.getContractFactory("RevocationRegistry");
    await expect(
      Registry.deploy(owner.address, ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(Registry, "ZeroAddress");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. authorizeIssuer / revokeIssuerAuthorization
// ─────────────────────────────────────────────────────────────────────────────

describe("2. authorizeIssuer / revokeIssuerAuthorization", function () {
  it("owner can authorize a new issuer and emits IssuerAuthorized", async function () {
    const { registry, owner, issuerA } = await loadFixture(deployFixture);
    await expect(
      registry.connect(owner).authorizeIssuer(issuerA.address, DID_A)
    )
      .to.emit(registry, "IssuerAuthorized")
      .withArgs(issuerA.address, DID_A);

    const rec = await registry.authorizedIssuers(issuerA.address);
    expect(rec.did).to.equal(DID_A);
    expect(rec.active).to.be.true;
  });

  it("non-owner cannot authorize — reverts OwnableUnauthorizedAccount", async function () {
    const { registry, issuerA, stranger } = await loadFixture(deployFixture);
    await expect(
      registry.connect(stranger).authorizeIssuer(issuerA.address, DID_A)
    ).to.be.reverted; // OZ v4 uses string revert for Ownable
  });

  it("rejects zero address issuer with ZeroAddress", async function () {
    const { registry, owner } = await loadFixture(deployFixture);
    await expect(
      registry.connect(owner).authorizeIssuer(ethers.ZeroAddress, DID_A)
    ).to.be.revertedWithCustomError(registry, "ZeroAddress");
  });

  it("rejects empty DID string with EmptyDID", async function () {
    const { registry, owner, issuerA } = await loadFixture(deployFixture);
    await expect(
      registry.connect(owner).authorizeIssuer(issuerA.address, "")
    ).to.be.revertedWithCustomError(registry, "EmptyDID");
  });

  it("owner can revoke issuer authorization and emits event", async function () {
    const { registry, owner, issuerA } = await loadFixture(authorizedFixture);
    await expect(
      registry.connect(owner).revokeIssuerAuthorization(issuerA.address)
    )
      .to.emit(registry, "IssuerAuthorizationRevoked")
      .withArgs(issuerA.address);

    const rec = await registry.authorizedIssuers(issuerA.address);
    expect(rec.active).to.be.false;
  });

  it("re-authorizing updates the DID", async function () {
    const { registry, owner, issuerA } = await loadFixture(authorizedFixture);
    await registry.connect(owner).authorizeIssuer(issuerA.address, DID_B);
    const rec = await registry.authorizedIssuers(issuerA.address);
    expect(rec.did).to.equal(DID_B);
    expect(rec.active).to.be.true;
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. onlyAuthorized modifier — boundary cases
// ─────────────────────────────────────────────────────────────────────────────

describe("3. onlyAuthorized modifier", function () {
  /**
   * Helper: attempt registerCertificate from signer with a given DID.
   * Returns the tx promise so callers can assert revert / success.
   */
  async function tryRegister(registry, signer, claimedDID, certID, pubSig) {
    return registry.connect(signer).registerCertificate(
      certID, MERKLE_ROOT, claimedDID,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
    );
  }

  it("stranger (not in mapping) → NotAuthorized", async function () {
    const { registry, stranger } = await loadFixture(authorizedFixture);
    const { certID, pubSig } = makeCert(100);
    await expect(
      tryRegister(registry, stranger, DID_A, certID, pubSig)
    ).to.be.revertedWithCustomError(registry, "NotAuthorized");
  });

  it("authorized address with wrong DID → DIDMismatch", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    // issuerA is registered with DID_A, but claims DID_B
    const { certID, pubSig } = makeCert(101);
    await expect(
      tryRegister(registry, issuerA, DID_B, certID, pubSig)
    ).to.be.revertedWithCustomError(registry, "DIDMismatch");
  });

  it("previously authorized then revoked → NotAuthorized", async function () {
    const { registry, owner, issuerA } = await loadFixture(authorizedFixture);
    await registry.connect(owner).revokeIssuerAuthorization(issuerA.address);
    const { certID, pubSig } = makeCert(102);
    await expect(
      tryRegister(registry, issuerA, DID_A, certID, pubSig)
    ).to.be.revertedWithCustomError(registry, "NotAuthorized");
  });

  it("correct address + correct DID → passes modifier", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const { certID, pubSig } = makeCert(103);
    // Should not revert (MockVerifier returns true)
    await expect(
      tryRegister(registry, issuerA, DID_A, certID, pubSig)
    ).to.not.be.reverted;
  });

  it("two different issuers cannot use each other's DID", async function () {
    const { registry, owner, issuerA, issuerB } = await loadFixture(authorizedFixture);
    await registry.connect(owner).authorizeIssuer(issuerB.address, DID_B);

    // issuerB tries to claim DID_A
    const { certID, pubSig } = makeCert(104);
    await expect(
      tryRegister(registry, issuerB, DID_A, certID, pubSig)
    ).to.be.revertedWithCustomError(registry, "DIDMismatch");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. registerCertificate
// ─────────────────────────────────────────────────────────────────────────────

describe("4. registerCertificate", function () {
  it("happy path: stores anchor correctly and emits CertificateRegistered", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const { certID, pubSig } = makeCert(10);

    const tx = registry.connect(issuerA).registerCertificate(
      certID, MERKLE_ROOT, DID_A,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
    );
    await expect(tx)
      .to.emit(registry, "CertificateRegistered")
      .withArgs(certID, issuerA.address, DID_A, MERKLE_ROOT, anyValue);

    const anchor = await registry.anchors(certID);
    expect(anchor.commitment).to.equal(certID);
    expect(anchor.merkleRoot).to.equal(MERKLE_ROOT);
    expect(anchor.submitter).to.equal(issuerA.address);
    expect(anchor.issuer_did).to.equal(DID_A);
    expect(anchor.revoked).to.be.false;
    expect(anchor.timestamp).to.be.gt(0n);
  });

  it("pubSignals[0] ≠ uint256(certID) → InvalidProof", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const { certID } = makeCert(11);
    const wrongPubSig = [BigInt(makeCert(999).certID)]; // deliberate mismatch
    await expect(
      registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, wrongPubSig
      )
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("verifier returns false → InvalidProof", async function () {
    const { registry, verifier, issuerA } = await loadFixture(authorizedFixture);
    await verifier.setShouldPass(false); // make verifier fail
    const { certID, pubSig } = makeCert(12);
    await expect(
      registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      )
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
    await verifier.setShouldPass(true); // restore
  });

  it("duplicate certID → CertAlreadyExists", async function () {
    const { registry, certID, pubSig, issuerA } = await loadFixture(oneCertFixture);
    await expect(
      registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      )
    ).to.be.revertedWithCustomError(registry, "CertAlreadyExists");
  });

  it("paused contract → reverts (Pausable)", async function () {
    const { registry, owner, issuerA } = await loadFixture(authorizedFixture);
    await registry.connect(owner).pause();
    const { certID, pubSig } = makeCert(13);
    await expect(
      registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      )
    ).to.be.reverted; // OZ v4 Pausable uses string "Pausable: paused"
  });

  it("two different issuers can each register their own certs", async function () {
    const { registry, owner, issuerA, issuerB } = await loadFixture(authorizedFixture);
    await registry.connect(owner).authorizeIssuer(issuerB.address, DID_B);

    const { certID: cA, pubSig: sA } = makeCert(14);
    const { certID: cB, pubSig: sB } = makeCert(15);

    await registry.connect(issuerA).registerCertificate(
      cA, MERKLE_ROOT, DID_A, ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, sA
    );
    await registry.connect(issuerB).registerCertificate(
      cB, MERKLE_ROOT, DID_B, ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, sB
    );

    expect((await registry.anchors(cA)).issuer_did).to.equal(DID_A);
    expect((await registry.anchors(cB)).issuer_did).to.equal(DID_B);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. revokeCertificate
// ─────────────────────────────────────────────────────────────────────────────

describe("5. revokeCertificate", function () {
  it("happy path: sets revoked=true and emits CertificateRevoked", async function () {
    const { registry, issuerA, certID } = await loadFixture(oneCertFixture);
    await expect(
      registry.connect(issuerA).revokeCertificate(certID, DID_A, "expired")
    )
      .to.emit(registry, "CertificateRevoked")
      .withArgs(certID, issuerA.address, "expired", anyValue);

    expect(await registry.isRevoked(certID)).to.be.true;
  });

  it("unknown certID → CertNotFound", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const unknown = makeCert(999).certID;
    await expect(
      registry.connect(issuerA).revokeCertificate(unknown, DID_A, "reason")
    ).to.be.revertedWithCustomError(registry, "CertNotFound");
  });

  it("already revoked → CertAlreadyRevoked", async function () {
    const { registry, issuerA, certID } = await loadFixture(oneCertFixture);
    await registry.connect(issuerA).revokeCertificate(certID, DID_A, "once");
    await expect(
      registry.connect(issuerA).revokeCertificate(certID, DID_A, "twice")
    ).to.be.revertedWithCustomError(registry, "CertAlreadyRevoked");
  });

  it("cert registered by issuerA cannot be revoked with issuerB's DID", async function () {
    const { registry, owner, issuerB, certID } = await loadFixture(oneCertFixture);
    await registry.connect(owner).authorizeIssuer(issuerB.address, DID_B);
    await expect(
      registry.connect(issuerB).revokeCertificate(certID, DID_B, "steal")
    ).to.be.revertedWithCustomError(registry, "AnchorDIDMismatch");
  });

  it("unauthorized caller → NotAuthorized", async function () {
    const { registry, stranger, certID } = await loadFixture(oneCertFixture);
    await expect(
      registry.connect(stranger).revokeCertificate(certID, DID_A, "reason")
    ).to.be.revertedWithCustomError(registry, "NotAuthorized");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. revokeCascade
// ─────────────────────────────────────────────────────────────────────────────

describe("6. revokeCascade", function () {

  /**
   * Helper: register a list of certs and wire them into a chain:
   *   certIDs[0] → certIDs[1] → certIDs[2] → ...
   */
  async function buildChain(registry, issuer, did, seeds) {
    const certs = seeds.map(makeCert);

    for (const { certID, pubSig } of certs) {
      await registry.connect(issuer).registerCertificate(
        certID, MERKLE_ROOT, did,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }

    for (let i = 0; i < certs.length - 1; i++) {
      await registry.connect(issuer).addDependency(
        certs[i].certID, certs[i + 1].certID, did
      );
    }

    return certs.map(c => c.certID);
  }

  it("no deps: revokes only the root cert", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const [root] = await buildChain(registry, issuerA, DID_A, [50]);

    await registry.connect(issuerA).revokeCascade(root, DID_A, "root only");

    expect(await registry.isRevoked(root)).to.be.true;
  });

  it("linear chain root→child→grandchild: all three revoked", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const [root, child, grand] = await buildChain(
      registry, issuerA, DID_A, [60, 61, 62]
    );

    const tx = registry.connect(issuerA).revokeCascade(root, DID_A, "chain");
    await expect(tx)
      .to.emit(registry, "CertificateRevoked")
      .withArgs(root, issuerA.address, "chain", anyValue);
    await (await tx);

    expect(await registry.isRevoked(root)).to.be.true;
    expect(await registry.isRevoked(child)).to.be.true;
    expect(await registry.isRevoked(grand)).to.be.true;
  });

  it("emits CascadeRevoked for each dependent (not the root)", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const [root, child, grand] = await buildChain(
      registry, issuerA, DID_A, [70, 71, 72]
    );

    const tx = await registry.connect(issuerA).revokeCascade(root, DID_A, "cascade");
    const receipt = await tx.wait();
    const cascadeEvents = receipt.logs
      .map(log => {
        try { return registry.interface.parseLog(log); } catch { return null; }
      })
      .filter(e => e && e.name === "CascadeRevoked");

    expect(cascadeEvents.length).to.equal(2); // child + grand
    const childEvt = cascadeEvents.find(e => e.args.childCertID === child);
    const grandEvt = cascadeEvents.find(e => e.args.childCertID === grand);
    expect(childEvt.args.depth).to.equal(1n);
    expect(grandEvt.args.depth).to.equal(2n);
  });

  it("branching tree: root→[child1, child2], child1→grandchild — all revoked", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const seeds   = [80, 81, 82, 83];
    const certs   = seeds.map(makeCert);
    for (const { certID, pubSig } of certs) {
      await registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }
    const [root, child1, child2, grand] = certs.map(c => c.certID);
    await registry.connect(issuerA).addDependency(root,   child1, DID_A);
    await registry.connect(issuerA).addDependency(root,   child2, DID_A);
    await registry.connect(issuerA).addDependency(child1, grand,  DID_A);

    await registry.connect(issuerA).revokeCascade(root, DID_A, "branch");

    expect(await registry.isRevoked(root)).to.be.true;
    expect(await registry.isRevoked(child1)).to.be.true;
    expect(await registry.isRevoked(child2)).to.be.true;
    expect(await registry.isRevoked(grand)).to.be.true;
  });

  it("already-revoked child is silently skipped (no revert)", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const [root, child] = await buildChain(registry, issuerA, DID_A, [90, 91]);
    // Pre-revoke child
    await registry.connect(issuerA).revokeCertificate(child, DID_A, "pre");

    // Cascade from root must not revert
    await expect(
      registry.connect(issuerA).revokeCascade(root, DID_A, "cascade")
    ).to.not.be.reverted;

    expect(await registry.isRevoked(root)).to.be.true;
    expect(await registry.isRevoked(child)).to.be.true; // was already revoked
  });

  it("root not found → CertNotFound", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const ghost = makeCert(999).certID;
    await expect(
      registry.connect(issuerA).revokeCascade(ghost, DID_A, "ghost")
    ).to.be.revertedWithCustomError(registry, "CertNotFound");
  });

  it("root already revoked → CertAlreadyRevoked", async function () {
    const { registry, issuerA, certID } = await loadFixture(oneCertFixture);
    await registry.connect(issuerA).revokeCertificate(certID, DID_A, "first");
    await expect(
      registry.connect(issuerA).revokeCascade(certID, DID_A, "second")
    ).to.be.revertedWithCustomError(registry, "CertAlreadyRevoked");
  });

  it("wrong DID for root → AnchorDIDMismatch", async function () {
    const { registry, owner, issuerA, issuerB, certID } = await loadFixture(oneCertFixture); // cert belongs to DID_A
    await registry.connect(owner).authorizeIssuer(issuerB.address, DID_B);
    await expect(
      registry.connect(issuerB).revokeCascade(certID, DID_B, "steal")
    ).to.be.revertedWithCustomError(registry, "AnchorDIDMismatch");
  });

  it("unauthorized caller → NotAuthorized", async function () {
    const { registry, stranger, certID } = await loadFixture(oneCertFixture);
    await expect(
      registry.connect(stranger).revokeCascade(certID, DID_A, "steal")
    ).to.be.revertedWithCustomError(registry, "NotAuthorized");
  });

  it("cascade on cert with no registered deps only revokes root", async function () {
    // deps entry simply doesn't exist — cascade should complete cleanly
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const { certID, pubSig } = makeCert(95);
    await registry.connect(issuerA).registerCertificate(
      certID, MERKLE_ROOT, DID_A,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
    );
    await expect(
      registry.connect(issuerA).revokeCascade(certID, DID_A, "leaf only")
    ).to.not.be.reverted;
    expect(await registry.isRevoked(certID)).to.be.true;
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. addDependency
// ─────────────────────────────────────────────────────────────────────────────

describe("7. addDependency", function () {
  it("happy path: adds dependency and can be verified via verifyCascade", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const [root, child] = await Promise.all([makeCert(200), makeCert(201)]);
    for (const { certID, pubSig } of [root, child]) {
      await registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }
    await registry.connect(issuerA).addDependency(root.certID, child.certID, DID_A);

    const [maxDepth, total] = await registry.verifyCascade(root.certID);
    expect(maxDepth).to.equal(1n);
    expect(total).to.equal(1n);
  });

  it("parent not registered → CertNotFound", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const { certID: child, pubSig } = makeCert(202);
    await registry.connect(issuerA).registerCertificate(
      child, MERKLE_ROOT, DID_A,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
    );
    const ghostParent = makeCert(998).certID;
    await expect(
      registry.connect(issuerA).addDependency(ghostParent, child, DID_A)
    ).to.be.revertedWithCustomError(registry, "CertNotFound");
  });

  it("child not registered → CertNotFound", async function () {
    const { registry, issuerA, certID: parent } = await loadFixture(oneCertFixture);
    const ghostChild = makeCert(997).certID;
    await expect(
      registry.connect(issuerA).addDependency(parent, ghostChild, DID_A)
    ).to.be.revertedWithCustomError(registry, "CertNotFound");
  });

  it("duplicate dependency → DependencyAlreadyExists", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const [p, c] = [makeCert(210), makeCert(211)];
    for (const { certID, pubSig } of [p, c]) {
      await registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }
    await registry.connect(issuerA).addDependency(p.certID, c.certID, DID_A);
    await expect(
      registry.connect(issuerA).addDependency(p.certID, c.certID, DID_A)
    ).to.be.revertedWithCustomError(registry, "DependencyAlreadyExists");
  });

  it("non-issuer of parent cannot add dependency → AnchorDIDMismatch", async function () {
    const { registry, owner, issuerA, issuerB } = await loadFixture(authorizedFixture);
    await registry.connect(owner).authorizeIssuer(issuerB.address, DID_B);

    // Register parent under DID_A (issuerA), child under DID_B (issuerB)
    const { certID: parentA, pubSig: psA } = makeCert(213);
    const { certID: childB,  pubSig: psB } = makeCert(214);
    await registry.connect(issuerA).registerCertificate(
      parentA, MERKLE_ROOT, DID_A,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, psA
    );
    await registry.connect(issuerB).registerCertificate(
      childB, MERKLE_ROOT, DID_B,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, psB
    );

    // issuerB (DID_B) tries to add a dependency on parentA (owned by DID_A)
    await expect(
      registry.connect(issuerB).addDependency(parentA, childB, DID_B)
    ).to.be.revertedWithCustomError(registry, "AnchorDIDMismatch");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Admin functions: setVerifier, pause / unpause
// ─────────────────────────────────────────────────────────────────────────────

describe("8. Admin functions", function () {
  it("setVerifier: owner can replace verifier and emits VerifierUpdated", async function () {
    const { registry, verifier, owner } = await loadFixture(deployFixture);
    const MockVerifier = await ethers.getContractFactory("MockVerifier");
    const newVerifier  = await MockVerifier.deploy(true);
    await newVerifier.waitForDeployment();

    await expect(
      registry.connect(owner).setVerifier(await newVerifier.getAddress())
    )
      .to.emit(registry, "VerifierUpdated")
      .withArgs(
        await verifier.getAddress(),
        await newVerifier.getAddress()
      );

    expect(await registry.verifier()).to.equal(await newVerifier.getAddress());
  });

  it("setVerifier: non-owner → reverts", async function () {
    const { registry, stranger } = await loadFixture(deployFixture);
    const MockVerifier = await ethers.getContractFactory("MockVerifier");
    const nv = await MockVerifier.deploy(true);
    await nv.waitForDeployment();
    await expect(
      registry.connect(stranger).setVerifier(await nv.getAddress())
    ).to.be.reverted;
  });

  it("setVerifier: zero address → ZeroAddress", async function () {
    const { registry, owner } = await loadFixture(deployFixture);
    await expect(
      registry.connect(owner).setVerifier(ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(registry, "ZeroAddress");
  });

  it("pause blocks registerCertificate; unpause re-enables it", async function () {
    const { registry, owner, issuerA } = await loadFixture(authorizedFixture);

    await registry.connect(owner).pause();
    const { certID, pubSig } = makeCert(300);
    await expect(
      registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      )
    ).to.be.reverted; // Pausable: paused

    await registry.connect(owner).unpause();
    await expect(
      registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      )
    ).to.not.be.reverted;
  });

  it("pause / unpause: non-owner cannot pause", async function () {
    const { registry, stranger } = await loadFixture(deployFixture);
    await expect(registry.connect(stranger).pause()).to.be.reverted;
  });

  it("Ownable2Step: ownership transfer requires acceptance", async function () {
    const { registry, owner, stranger } = await loadFixture(deployFixture);
    await registry.connect(owner).transferOwnership(stranger.address);
    // pendingOwner set but not yet owner
    expect(await registry.owner()).to.equal(owner.address);
    expect(await registry.pendingOwner()).to.equal(stranger.address);

    await registry.connect(stranger).acceptOwnership();
    expect(await registry.owner()).to.equal(stranger.address);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. View functions: isRevoked, verifyCertificate, verifyCascade
// ─────────────────────────────────────────────────────────────────────────────

describe("9. View functions", function () {
  it("isRevoked returns false for active cert and true after revocation", async function () {
    const { registry, issuerA, certID } = await loadFixture(oneCertFixture);
    expect(await registry.isRevoked(certID)).to.be.false;
    await registry.connect(issuerA).revokeCertificate(certID, DID_A, "test");
    expect(await registry.isRevoked(certID)).to.be.true;
  });

  it("isRevoked returns false for unknown certID (no revert)", async function () {
    const { registry } = await loadFixture(deployFixture);
    const ghost = makeCert(9999).certID;
    expect(await registry.isRevoked(ghost)).to.be.false;
  });

  it("verifyCertificate delegates to verifier — returns true when verifier passes", async function () {
    const { registry } = await loadFixture(deployFixture);
    const { pubSig } = makeCert(400);
    const result = await registry.verifyCertificate(
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
    );
    expect(result).to.be.true;
  });

  it("verifyCertificate returns false when verifier fails", async function () {
    const { registry, verifier } = await loadFixture(deployFixture);
    await verifier.setShouldPass(false);
    const { pubSig } = makeCert(401);
    const result = await registry.verifyCertificate(
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
    );
    expect(result).to.be.false;
    await verifier.setShouldPass(true);
  });

  it("verifyCascade: returns (0,0) for cert with no deps", async function () {
    const { registry, certID } = await loadFixture(oneCertFixture);
    const [maxDepth, total] = await registry.verifyCascade(certID);
    expect(maxDepth).to.equal(0n);
    expect(total).to.equal(0n);
  });

  it("verifyCascade: 2-level linear chain → maxDepth=2, total=2", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const certs = [makeCert(500), makeCert(501), makeCert(502)];
    for (const { certID, pubSig } of certs) {
      await registry.connect(issuerA).registerCertificate(
        certID, MERKLE_ROOT, DID_A,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }
    await registry.connect(issuerA).addDependency(certs[0].certID, certs[1].certID, DID_A);
    await registry.connect(issuerA).addDependency(certs[1].certID, certs[2].certID, DID_A);

    const [maxDepth, total] = await registry.verifyCascade(certs[0].certID);
    expect(maxDepth).to.equal(2n);
    expect(total).to.equal(2n);
  });
});

// (anyValue is imported from @nomicfoundation/hardhat-chai-matchers/withArgs)

// ─────────────────────────────────────────────────────────────────────────────
// 10. Gas benchmark: revokeCascade across topology & depth
// ─────────────────────────────────────────────────────────────────────────────

describe("10. Gas: revokeCascade benchmark", function () {

  /**
   * Shared results table collected by each benchmark `it` block.
   * Printed and validated in the `after` hook.
   *
   * Record shape:
   *   { label, topology, depth, nodes, gasUsed, gasPerNode }
   */
  const gasReport = [];

  // ── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Register `depth + 1` certs (root + depth dependents) and wire them
   * into a single linear chain:  root → dep1 → dep2 → … → depN
   *
   * Seed layout: seedBase, seedBase+1, …, seedBase+depth
   * Returns: array of certIDs in chain order (index 0 = root).
   */
  async function buildLinearChain(registry, issuer, did, seedBase, depth) {
    const certs = Array.from({ length: depth + 1 }, (_, i) => makeCert(seedBase + i));
    for (const { certID, pubSig } of certs) {
      await registry.connect(issuer).registerCertificate(
        certID, MERKLE_ROOT, did,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }
    for (let i = 0; i < certs.length - 1; i++) {
      await registry.connect(issuer).addDependency(
        certs[i].certID, certs[i + 1].certID, did
      );
    }
    return certs.map(c => c.certID);
  }

  /**
   * Register a star topology: one root with `fanOut` direct children,
   * no grandchildren (BFS depth = 1).
   *
   * Seed layout: seedBase = root, seedBase+1..seedBase+fanOut = children.
   * Returns: [root, child1, child2, …, childN]
   */
  async function buildStar(registry, issuer, did, seedBase, fanOut) {
    const root = makeCert(seedBase);
    await registry.connect(issuer).registerCertificate(
      root.certID, MERKLE_ROOT, did,
      ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, root.pubSig
    );
    const children = [];
    for (let i = 1; i <= fanOut; i++) {
      const c = makeCert(seedBase + i);
      await registry.connect(issuer).registerCertificate(
        c.certID, MERKLE_ROOT, did,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, c.pubSig
      );
      await registry.connect(issuer).addDependency(root.certID, c.certID, did);
      children.push(c.certID);
    }
    return [root.certID, ...children];
  }

  /**
   * Register a balanced k-ary tree of the given depth.
   * Total nodes = (k^(depth+1) − 1) / (k − 1)
   *
   * Seeds are allocated sequentially starting at seedBase (BFS order).
   * Returns: all certIDs in BFS order (index 0 = root).
   */
  async function buildBalancedTree(registry, issuer, did, seedBase, fanOut, depth) {
    // Allocate seeds BFS-order
    const total = Math.round((Math.pow(fanOut, depth + 1) - 1) / (fanOut - 1));
    const certs = Array.from({ length: total }, (_, i) => makeCert(seedBase + i));

    for (const { certID, pubSig } of certs) {
      await registry.connect(issuer).registerCertificate(
        certID, MERKLE_ROOT, did,
        ZERO_PROOF.pA, ZERO_PROOF.pB, ZERO_PROOF.pC, pubSig
      );
    }
    // Wire edges: parent at index i has children at i*fanOut+1 … i*fanOut+fanOut
    for (let parent = 0; parent < total; parent++) {
      for (let k = 1; k <= fanOut; k++) {
        const child = parent * fanOut + k;
        if (child < total) {
          await registry.connect(issuer).addDependency(
            certs[parent].certID, certs[child].certID, did
          );
        }
      }
    }
    return certs.map(c => c.certID);
  }

  // ── Benchmark helper: run cascade, collect gas ─────────────────────────────

  /**
   * Execute revokeCascade and return { gasUsed, gasPerNode }.
   * Also asserts every cert in `allCertIDs` is revoked afterwards.
   */
  async function measureCascade(registry, issuer, did, rootCertID, allCertIDs) {
    const tx      = await registry.connect(issuer).revokeCascade(rootCertID, did, "gas-bench");
    const receipt = await tx.wait();
    const gasUsed   = Number(receipt.gasUsed);
    const gasPerNode = Math.round(gasUsed / allCertIDs.length);

    for (const id of allCertIDs) {
      expect(await registry.isRevoked(id)).to.be.true;
    }
    return { gasUsed, gasPerNode };
  }

  // ── Linear chain benchmarks ────────────────────────────────────────────────

  it("linear depth  5  (6 nodes, seeds 1001-1006)", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const ids = await buildLinearChain(registry, issuerA, DID_A, 1001, 5);
    const { gasUsed, gasPerNode } = await measureCascade(
      registry, issuerA, DID_A, ids[0], ids
    );
    gasReport.push({ label: "Linear  5", topology: "linear", depth: 5, nodes: ids.length, gasUsed, gasPerNode });

    // Upper-bound guard: must finish well within a single block
    expect(gasUsed).to.be.lt(5_000_000, "depth-5 cascade exceeded 5 M gas");
  });

  it("linear depth 10 (11 nodes, seeds 1101-1111)", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const ids = await buildLinearChain(registry, issuerA, DID_A, 1101, 10);
    const { gasUsed, gasPerNode } = await measureCascade(
      registry, issuerA, DID_A, ids[0], ids
    );
    gasReport.push({ label: "Linear 10", topology: "linear", depth: 10, nodes: ids.length, gasUsed, gasPerNode });

    expect(gasUsed).to.be.lt(5_000_000, "depth-10 cascade exceeded 5 M gas");
  });

  it("linear depth 20 (21 nodes, seeds 1201-1221)", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const ids = await buildLinearChain(registry, issuerA, DID_A, 1201, 20);
    const { gasUsed, gasPerNode } = await measureCascade(
      registry, issuerA, DID_A, ids[0], ids
    );
    gasReport.push({ label: "Linear 20", topology: "linear", depth: 20, nodes: ids.length, gasUsed, gasPerNode });

    expect(gasUsed).to.be.lt(8_000_000, "depth-20 cascade exceeded 8 M gas");
  });

  // ── Star topology (depth=1, high fan-out) ─────────────────────────────────

  it("star  depth  1  (11 nodes, fan-out 10, seeds 1301-1311)", async function () {
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    // 1 root + 10 direct children = 11 nodes, same count as linear-10
    const ids = await buildStar(registry, issuerA, DID_A, 1301, 10);
    const { gasUsed, gasPerNode } = await measureCascade(
      registry, issuerA, DID_A, ids[0], ids
    );
    gasReport.push({ label: "Star   10", topology: "star",   depth: 1,  nodes: ids.length, gasUsed, gasPerNode });

    expect(gasUsed).to.be.lt(5_000_000, "star-10 cascade exceeded 5 M gas");
  });

  // ── Balanced ternary tree (branching factor 3, depth 2) ───────────────────

  it("balanced tree  fan-out=3, depth=2  (13 nodes, seeds 1400-1412)", async function () {
    // Nodes: 1 root + 3 children + 9 grandchildren = 13
    const { registry, issuerA } = await loadFixture(authorizedFixture);
    const ids = await buildBalancedTree(registry, issuerA, DID_A, 1400, 3, 2);
    expect(ids.length).to.equal(13);
    const { gasUsed, gasPerNode } = await measureCascade(
      registry, issuerA, DID_A, ids[0], ids
    );
    gasReport.push({ label: "Tree 3×2 ", topology: "tree-3-2", depth: 2,  nodes: 13, gasUsed, gasPerNode });

    expect(gasUsed).to.be.lt(5_000_000, "tree-3×2 cascade exceeded 5 M gas");
  });

  // ── Cross-run analysis tests ───────────────────────────────────────────────

  it("linear gas grows monotonically with depth", function () {
    const linear = gasReport
      .filter(r => r.topology === "linear")
      .sort((a, b) => a.depth - b.depth);
    if (linear.length < 2) return this.skip();
    for (let i = 1; i < linear.length; i++) {
      expect(linear[i].gasUsed).to.be.gt(
        linear[i - 1].gasUsed,
        `gas(depth=${linear[i].depth}) should exceed gas(depth=${linear[i - 1].depth})`
      );
    }
  });

  it("gas growth is linear, not exponential (Δgas/level within 50% variance)", function () {
    const linear = gasReport
      .filter(r => r.topology === "linear")
      .sort((a, b) => a.depth - b.depth);
    if (linear.length < 3) return this.skip();

    const [r5, r10, r20] = linear;
    const gasPerLevel_5_to_10  = (r10.gasUsed - r5.gasUsed)  / (r10.depth - r5.depth);
    const gasPerLevel_10_to_20 = (r20.gasUsed - r10.gasUsed) / (r20.depth - r10.depth);

    const ratio = Math.max(gasPerLevel_5_to_10, gasPerLevel_10_to_20) /
                  Math.min(gasPerLevel_5_to_10, gasPerLevel_10_to_20);

    expect(ratio).to.be.lt(
      1.5,
      `gas/level ratio=${ratio.toFixed(2)} exceeds 1.5 — growth may be non-linear`
    );
  });

  it("star revokes same node-count as linear-10 with less or comparable gas", function () {
    const linear10 = gasReport.find(r => r.topology === "linear" && r.depth === 10);
    const star10   = gasReport.find(r => r.topology === "star");
    if (!linear10 || !star10) return this.skip();

    // Both handle 11 nodes; star should be <= linear because BFS depth is 1
    // (all children are warm-loaded in a single level vs. 10 sequential SLOAD walks).
    // Allow up to +20% headroom for any BFS bookkeeping overhead differences.
    expect(star10.gasUsed).to.be.lte(
      Math.round(linear10.gasUsed * 1.20),
      `star(${star10.gasUsed}) should be ≤ 120% of linear-10(${linear10.gasUsed})`
    );
  });

  // ── Summary table (printed after all benchmarks) ──────────────────────────

  after(function () {
    if (gasReport.length === 0) return;

    const COL = { label: 14, depth: 7, nodes: 7, gas: 13, perNode: 11 };
    const pad  = (s, n) => String(s).padStart(n);
    const lpad = (s, n) => String(s).padEnd(n);
    const sep  = (c1, fill, c2, c3) =>
      c1 + fill.repeat(COL.label + 2) + c3 +
      fill.repeat(COL.depth  + 2) + c3 +
      fill.repeat(COL.nodes  + 2) + c3 +
      fill.repeat(COL.gas    + 2) + c3 +
      fill.repeat(COL.perNode + 2) + c2;

    const row  = (label, depth, nodes, gasUsed, perNode) =>
      "  │ " + lpad(label,   COL.label) +
      " │ " + pad(depth,    COL.depth)  +
      " │ " + pad(nodes,    COL.nodes)  +
      " │ " + pad(gasUsed.toLocaleString(), COL.gas) +
      " │ " + pad(perNode.toLocaleString(), COL.perNode) + " │";

    console.log("\n  " + sep("╔", "═", "╗", "╦"));
    console.log("  ║" + " revokeCascade Gas Benchmark".padEnd(
      COL.label + COL.depth + COL.nodes + COL.gas + COL.perNode + 14
    ) + "║");
    console.log("  " + sep("╠", "═", "╣", "╬"));
    console.log("  │ " +
      lpad("Topology",     COL.label) + " │ " +
      pad("Depth",         COL.depth) + " │ " +
      pad("Nodes",         COL.nodes) + " │ " +
      pad("gasUsed",       COL.gas)   + " │ " +
      pad("gas/node",      COL.perNode) + " │"
    );
    console.log("  " + sep("╠", "═", "╣", "╬"));
    for (const r of gasReport) {
      console.log(row(r.label, r.depth, r.nodes, r.gasUsed, r.gasPerNode));
    }
    console.log("  " + sep("╚", "═", "╝", "╩"));

    // Δgas per additional level for linear topology
    const linear = gasReport
      .filter(r => r.topology === "linear")
      .sort((a, b) => a.depth - b.depth);
    if (linear.length >= 2) {
      console.log("\n  Δ gas per additional level (linear topology):");
      for (let i = 1; i < linear.length; i++) {
        const depthDiff = linear[i].depth - linear[i - 1].depth;
        const gasDiff   = linear[i].gasUsed - linear[i - 1].gasUsed;
        const perLevel  = Math.round(gasDiff / depthDiff);
        console.log(
          `    depth ${linear[i-1].depth.toString().padStart(2)} → ${linear[i].depth.toString().padStart(2)} : ` +
          `Δ ${gasDiff.toLocaleString()} gas over ${depthDiff} levels ` +
          `(≈ ${perLevel.toLocaleString()} gas/level)`
        );
      }
    }
    console.log();
  });
});