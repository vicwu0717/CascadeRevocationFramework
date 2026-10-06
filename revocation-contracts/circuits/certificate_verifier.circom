pragma circom 2.1.6;

// circomlib: Poseidon hash (ZK-friendly, BN254 native)
include "../node_modules/circomlib/circuits/poseidon.circom";

// ────────────────────────────────────────────────────────────────────────────
// MerkleProof(levels)
//
// Inputs
//   leaf              : leaf node value
//   pathElements[levels] : sibling hashes along the path from leaf to root
//   pathIndices[levels]  : 0 = current node is LEFT child
//                          1 = current node is RIGHT child
// Output
//   root              : computed Merkle root
//
// Hash function: Poseidon(2)  (matches on-chain Poseidon if needed for cross-check)
// ────────────────────────────────────────────────────────────────────────────
template MerkleProof(levels) {
    signal input  leaf;
    signal input  pathElements[levels];
    signal input  pathIndices[levels];
    signal output root;

    signal nodes[levels + 1];
    signal sl[levels];          // swap amount per level

    component poseidon[levels];

    nodes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Swap trick (quadratic constraint):
        //   sl[i] = pathIndices[i] * (pathElements[i] - nodes[i])
        //   left  = nodes[i]       + sl[i]   → pathIndex=0: nodes[i]       | pathIndex=1: pathElements[i]
        //   right = pathElements[i] - sl[i]  → pathIndex=0: pathElements[i]| pathIndex=1: nodes[i]
        sl[i] <== pathIndices[i] * (pathElements[i] - nodes[i]);

        poseidon[i]         = Poseidon(2);
        poseidon[i].inputs[0] <== nodes[i]        + sl[i];   // left
        poseidon[i].inputs[1] <== pathElements[i] - sl[i];   // right

        nodes[i + 1] <== poseidon[i].out;
    }

    root <== nodes[levels];
}

// ────────────────────────────────────────────────────────────────────────────
// CertificateVerifier(levels, nAttr)
//
// Proves that the prover knows a certificate (certID, attributes[], issuerSecret)
// whose Poseidon leaf hash is included in a Merkle tree with the given root.
//
// PUBLIC signals  (visible on-chain via pubSignals):
//   certID          → pubSignals[0]  — matched to uint256(certID) in RevocationRegistry
//
// PRIVATE signals  (never revealed, zero-knowledge):
//   attributes[nAttr]
//   issuerSecret
//   merkleRoot          — constrained to equal the computed root
//   pathElements[levels]
//   pathIndices[levels]
//
// Parameters (compile-time):
//   levels = 20   (Merkle tree depth, supports up to 2^20 ≈ 1M certificates)
//   nAttr  = 5    (number of certificate attributes)
//
// Constraint count ≈ 24,000  (fits in pot15, 2^15 = 32,768 constraints)
// ────────────────────────────────────────────────────────────────────────────
template CertificateVerifier(levels, nAttr) {

    // ── Public input ──────────────────────────────────────────────────────
    signal input certID;               // certificate identifier (public)

    // ── Private inputs ────────────────────────────────────────────────────
    signal input attributes[nAttr];   // certificate attribute values
    signal input issuerSecret;        // issuer secret (proves issuer identity)
    signal input merkleRoot;          // Merkle root (private; constrained below)
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // ── Step 1 : Compute leaf = Poseidon(certID, attr[0..4], issuerSecret) ──
    //   Total inputs = 1 + nAttr + 1 = nAttr + 2 = 7
    component leafHasher = Poseidon(nAttr + 2);
    leafHasher.inputs[0] <== certID;
    for (var i = 0; i < nAttr; i++) {
        leafHasher.inputs[i + 1] <== attributes[i];
    }
    leafHasher.inputs[nAttr + 1] <== issuerSecret;

    // ── Step 2 : Verify Merkle inclusion proof ────────────────────────────
    component merkleCheck = MerkleProof(levels);
    merkleCheck.leaf <== leafHasher.out;
    for (var i = 0; i < levels; i++) {
        merkleCheck.pathElements[i] <== pathElements[i];
        merkleCheck.pathIndices[i]  <== pathIndices[i];
    }

    // ── Step 3 : Constrain claimed root == computed root ──────────────────
    //   This is the core ZK statement:
    //   "I know (attributes, issuerSecret, path) such that
    //    Poseidon(certID, attrs..., secret) is a leaf in the tree rooted at merkleRoot"
    merkleRoot === merkleCheck.root;
}

// ── Main component ────────────────────────────────────────────────────────
//   { public [certID] }  →  exactly 1 public signal  →  uint256[1] pubSignals
//   matches IGroth16Verifier.verifyProof(..., uint256[1] _pubSignals)
component main { public [certID] } = CertificateVerifier(20, 5);
