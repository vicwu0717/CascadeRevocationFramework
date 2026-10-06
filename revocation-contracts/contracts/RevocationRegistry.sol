// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/IGroth16Verifier.sol";

/**
 * @title RevocationRegistry
 * @notice Privacy-preserving supply-chain certificate revocation registry.
 *
 *         Key properties:
 *  - Certificate identifiers and Merkle proofs are verified off-chain;
 *    only a zk-SNARK proof is submitted on-chain (zero knowledge).
 *  - Each anchor (certificate commitment) records the submitting address
 *    AND the issuer's DID so that both can be authenticated.
 *  - Cascading revocation propagates revocation to dependent certificates
 *    up to MAX_CASCADE_DEPTH levels deep (gas-bounded).
 *  - The Groth16 verifier is a separate deployed contract; upgrading the
 *    VK only requires redeploying Groth16Verifier and calling setVerifier().
 *
 *         Architecture:
 *  ┌──────────────────────┐        ┌──────────────────────┐
 *  │  RevocationRegistry  │──calls─▶  Groth16Verifier     │
 *  │  (OZ: Ownable2Step,  │        │  (IGroth16Verifier)  │
 *  │   Pausable,          │        └──────────────────────┘
 *  │   ReentrancyGuard)   │
 *  └──────────────────────┘
 *
 * @dev Toolchain: Solidity 0.8.19, OpenZeppelin v4.9.x, Hardhat.
 */
contract RevocationRegistry is Ownable2Step, Pausable, ReentrancyGuard {

    // ═══════════════════════════════════════════════════════════════
    // SECTION A: Types & state
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Maximum cascading-revocation depth.
     *         Prevents unbounded gas usage in deep dependency trees.
     */
    uint256 public constant MAX_CASCADE_DEPTH = 32;

    /**
     * @notice Anchor record written for each registered certificate.
     * @param commitment  Poseidon hash of certificate attributes (leaf value).
     * @param merkleRoot  Merkle root of the issuer's certificate tree at
     *                    registration time.
     * @param submitter   msg.sender who called registerCertificate().
     * @param issuer_did  DID string of the issuing organisation, bound to
     *                    submitter via authorizedIssuers mapping.
     * @param timestamp   Block timestamp of registration.
     * @param revoked     True once the certificate has been revoked.
     */
    struct Anchor {
        bytes32 commitment;
        bytes32 merkleRoot;
        address submitter;
        string  issuer_did;
        uint256 timestamp;
        bool    revoked;
    }

    /**
     * @notice Issuer record stored per authorized address.
     * @param did      Canonical DID string for this issuer.
     * @param active   True if the issuer is currently authorized.
     */
    struct IssuerRecord {
        string  did;
        bool    active;
    }

    /// @notice certID → Anchor  (certID is the leaf commitment cast to bytes32)
    mapping(bytes32 => Anchor) public anchors;

    /// @notice address → IssuerRecord
    mapping(address => IssuerRecord) public authorizedIssuers;

    /// @notice certID → list of dependent certIDs (children in cascade graph)
    mapping(bytes32 => bytes32[]) public dependencies;

    /// @notice The deployed Groth16Verifier contract
    IGroth16Verifier public verifier;

    // ═══════════════════════════════════════════════════════════════
    // SECTION B: Events
    // ═══════════════════════════════════════════════════════════════

    event CertificateRegistered(
        bytes32 indexed certID,
        address indexed submitter,
        string          issuerDID,
        bytes32         merkleRoot,
        uint256         timestamp
    );
    event CertificateRevoked(
        bytes32 indexed certID,
        address indexed revoker,
        string          reason,
        uint256         timestamp
    );
    event CascadeRevoked(
        bytes32 indexed parentCertID,
        bytes32 indexed childCertID,
        uint256         depth
    );
    event IssuerAuthorized(address indexed issuer, string did);
    event IssuerAuthorizationRevoked(address indexed issuer);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    // ═══════════════════════════════════════════════════════════════
    // SECTION C: Custom errors  (cheaper than require strings)
    // ═══════════════════════════════════════════════════════════════

    error NotAuthorized(address caller, string claimedDID);
    error DIDMismatch(address caller, string claimedDID);
    error CertAlreadyExists(bytes32 certID);
    error CertNotFound(bytes32 certID);
    error CertAlreadyRevoked(bytes32 certID);
    error InvalidProof();
    error ZeroAddress();
    error EmptyDID();
    error DependencyAlreadyExists(bytes32 parent, bytes32 child);
    error CascadeDepthExceeded(uint256 depth);
    error AnchorDIDMismatch(bytes32 certID, string expected, string provided);

    // ═══════════════════════════════════════════════════════════════
    // SECTION D: Modifiers
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Dual-layer authorization:
     *  (1) msg.sender must be in authorizedIssuers and be active.
     *  (2) The claimed DID must match the DID registered for msg.sender.
     */
    modifier onlyAuthorized(string calldata claimedDID) {
        IssuerRecord storage rec = authorizedIssuers[msg.sender];
        if (!rec.active)                           revert NotAuthorized(msg.sender, claimedDID);
        if (keccak256(bytes(rec.did)) !=
            keccak256(bytes(claimedDID)))          revert DIDMismatch(msg.sender, claimedDID);
        _;
    }

    // ═══════════════════════════════════════════════════════════════
    // SECTION E: Constructor
    // ═══════════════════════════════════════════════════════════════

    /**
     * @param _owner     Address that will own this contract (Ownable2Step).
     * @param _verifier  Address of the deployed Groth16Verifier contract.
     */
    constructor(address _owner, address _verifier) {
        if (_owner    == address(0)) revert ZeroAddress();
        if (_verifier == address(0)) revert ZeroAddress();
        // OZ v4 Ownable constructor sets owner to msg.sender by default;
        // override to _owner via _transferOwnership.
        _transferOwnership(_owner);
        verifier = IGroth16Verifier(_verifier);
    }

    // ═══════════════════════════════════════════════════════════════
    // SECTION F: Core certificate operations
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Register a certificate on-chain after verifying the zk-SNARK.
     *
     * @param certID      Leaf commitment (bytes32) — the certificate's
     *                    on-chain identifier.
     * @param merkleRoot  Current Merkle root of the issuer's certificate tree.
     * @param claimedDID  DID string of the issuer (must match the authorized
     *                    record for msg.sender).
     * @param _pA         Proof element A.
     * @param _pB         Proof element B.
     * @param _pC         Proof element C.
     * @param _pubSignals Public inputs: [0] = leaf commitment as uint256.
     *
     * @dev The circuit's single public input is the leaf commitment, which
     *      equals certID cast to uint256.  This ties the on-chain anchor
     *      to the specific certificate attributes committed in the proof.
     */
    function registerCertificate(
        bytes32             certID,
        bytes32             merkleRoot,
        string  calldata    claimedDID,
        uint256[2]    calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2]    calldata _pC,
        uint256[1]    calldata _pubSignals
    )
        external
        whenNotPaused
        nonReentrant
        onlyAuthorized(claimedDID)
    {
        if (anchors[certID].timestamp != 0) revert CertAlreadyExists(certID);

        // Verify zk-SNARK: public input must match the certID being registered
        if (_pubSignals[0] != uint256(certID))   revert InvalidProof();
        if (!verifier.verifyProof(_pA, _pB, _pC, _pubSignals)) revert InvalidProof();

        anchors[certID] = Anchor({
            commitment: certID,
            merkleRoot: merkleRoot,
            submitter:  msg.sender,
            issuer_did: claimedDID,
            timestamp:  block.timestamp,
            revoked:    false
        });

        emit CertificateRegistered(certID, msg.sender, claimedDID, merkleRoot, block.timestamp);
    }

    /**
     * @notice Revoke a single certificate (no cascade).
     *
     * @param certID     Certificate to revoke.
     * @param claimedDID DID of the caller (must match anchor.issuer_did).
     * @param reason     Human-readable revocation reason (e.g. "expired").
     */
    function revokeCertificate(
        bytes32          certID,
        string calldata  claimedDID,
        string calldata  reason
    )
        external
        whenNotPaused
        nonReentrant
        onlyAuthorized(claimedDID)
    {
        Anchor storage a = anchors[certID];
        if (a.timestamp == 0)  revert CertNotFound(certID);
        if (a.revoked)         revert CertAlreadyRevoked(certID);

        // Extra check: only the original issuer DID may revoke this cert
        if (keccak256(bytes(a.issuer_did)) != keccak256(bytes(claimedDID)))
            revert AnchorDIDMismatch(certID, a.issuer_did, claimedDID);

        a.revoked = true;
        emit CertificateRevoked(certID, msg.sender, reason, block.timestamp);
    }

    /**
     * @notice Revoke a certificate AND cascade revocation to all dependents.
     *
     * @param certID     Root certificate of the cascade.
     * @param claimedDID DID of the caller.
     * @param reason     Revocation reason (applied to root only).
     *
     * @dev Uses an iterative BFS up to MAX_CASCADE_DEPTH to avoid stack
     *      overflow and cap gas consumption.  Certificates already revoked
     *      are silently skipped.
     */
    function revokeCascade(
        bytes32          certID,
        string calldata  claimedDID,
        string calldata  reason
    )
        external
        whenNotPaused
        nonReentrant
        onlyAuthorized(claimedDID)
    {
        Anchor storage root = anchors[certID];
        if (root.timestamp == 0) revert CertNotFound(certID);
        if (root.revoked)        revert CertAlreadyRevoked(certID);

        if (keccak256(bytes(root.issuer_did)) != keccak256(bytes(claimedDID)))
            revert AnchorDIDMismatch(certID, root.issuer_did, claimedDID);

        // Revoke root
        root.revoked = true;
        emit CertificateRevoked(certID, msg.sender, reason, block.timestamp);

        // BFS cascade — bounded at MAX_CASCADE_DEPTH
        bytes32[] memory queue = new bytes32[](MAX_CASCADE_DEPTH * 8);
        uint256 head = 0;
        uint256 tail = 0;
        uint256[] memory depthTrack = new uint256[](MAX_CASCADE_DEPTH * 8);

        // Enqueue direct children
        bytes32[] storage rootDeps = dependencies[certID];
        for (uint256 i = 0; i < rootDeps.length; i++) {
            if (tail < queue.length) {
                queue[tail]      = rootDeps[i];
                depthTrack[tail] = 1;
                tail++;
            }
        }

        while (head < tail) {
            bytes32 cur  = queue[head];
            uint256 dep  = depthTrack[head];
            head++;

            if (dep > MAX_CASCADE_DEPTH) revert CascadeDepthExceeded(dep);

            Anchor storage ca = anchors[cur];
            if (ca.timestamp == 0 || ca.revoked) continue; // skip missing / already revoked

            ca.revoked = true;
            emit CascadeRevoked(certID, cur, dep);

            // Enqueue children
            bytes32[] storage childDeps = dependencies[cur];
            for (uint256 j = 0; j < childDeps.length; j++) {
                if (tail < queue.length) {
                    queue[tail]      = childDeps[j];
                    depthTrack[tail] = dep + 1;
                    tail++;
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // SECTION G: Dependency management
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Register a dependency edge: parent → child.
     *         The parent certificate's revocation will cascade to the child.
     *
     * @param parent     Parent certificate ID.
     * @param child      Child (dependent) certificate ID.
     * @param claimedDID DID of the caller (must be issuer of the parent cert).
     */
    function addDependency(
        bytes32         parent,
        bytes32         child,
        string calldata claimedDID
    )
        external
        whenNotPaused
        onlyAuthorized(claimedDID)
    {
        if (anchors[parent].timestamp == 0) revert CertNotFound(parent);
        if (anchors[child].timestamp  == 0) revert CertNotFound(child);
        if (keccak256(bytes(anchors[parent].issuer_did)) != keccak256(bytes(claimedDID)))
            revert AnchorDIDMismatch(parent, anchors[parent].issuer_did, claimedDID);

        // Deduplicate
        bytes32[] storage deps = dependencies[parent];
        for (uint256 i = 0; i < deps.length; i++) {
            if (deps[i] == child) revert DependencyAlreadyExists(parent, child);
        }
        deps.push(child);
    }

    // ═══════════════════════════════════════════════════════════════
    // SECTION H: View functions
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Check whether a certificate is revoked (privacy-neutral: no
     *         attribute data is exposed).
     */
    function isRevoked(bytes32 certID) external view returns (bool) {
        return anchors[certID].revoked;
    }

    /**
     * @notice Verify that a submitted proof is valid WITHOUT writing state.
     *         Useful for off-chain relayers to pre-validate before submitting.
     */
    function verifyCertificate(
        uint256[2]    calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2]    calldata _pC,
        uint256[1]    calldata _pubSignals
    ) external view returns (bool) {
        return verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
    }

    /**
     * @notice Return the cascade depth for a given root cert (read-only BFS).
     *         Returns 0 if the cert has no dependencies.
     */
    function verifyCascade(bytes32 certID)
        external view returns (uint256 maxDepth, uint256 totalDescendants)
    {
        bytes32[] memory queue = new bytes32[](MAX_CASCADE_DEPTH * 8);
        uint256[] memory depths = new uint256[](MAX_CASCADE_DEPTH * 8);
        uint256 head = 0;
        uint256 tail = 0;

        bytes32[] storage rootDeps = dependencies[certID];
        for (uint256 i = 0; i < rootDeps.length; i++) {
            if (tail < queue.length) { queue[tail] = rootDeps[i]; depths[tail] = 1; tail++; }
        }

        while (head < tail) {
            bytes32 cur = queue[head];
            uint256 d   = depths[head];
            head++;
            if (d > maxDepth) maxDepth = d;
            totalDescendants++;
            if (d >= MAX_CASCADE_DEPTH) continue;
            bytes32[] storage childDeps = dependencies[cur];
            for (uint256 j = 0; j < childDeps.length; j++) {
                if (tail < queue.length) { queue[tail] = childDeps[j]; depths[tail] = d+1; tail++; }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // SECTION I: Admin functions (onlyOwner)
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Add or update an authorized issuer.
     * @param issuer  Ethereum address of the issuer.
     * @param did     DID string to bind to this address.
     */
    function authorizeIssuer(address issuer, string calldata did) external onlyOwner {
        if (issuer == address(0)) revert ZeroAddress();
        if (bytes(did).length  == 0) revert EmptyDID();
        authorizedIssuers[issuer] = IssuerRecord({ did: did, active: true });
        emit IssuerAuthorized(issuer, did);
    }

    /**
     * @notice Remove an issuer's authorization.
     * @param issuer  Address to deauthorize.
     */
    function revokeIssuerAuthorization(address issuer) external onlyOwner {
        authorizedIssuers[issuer].active = false;
        emit IssuerAuthorizationRevoked(issuer);
    }

    /**
     * @notice Replace the Groth16 verifier contract (e.g. after a new ceremony).
     * @param _newVerifier  Address of the newly deployed Groth16Verifier.
     */
    function setVerifier(address _newVerifier) external onlyOwner {
        if (_newVerifier == address(0)) revert ZeroAddress();
        address old = address(verifier);
        verifier = IGroth16Verifier(_newVerifier);
        emit VerifierUpdated(old, _newVerifier);
    }

    /// @notice Pause all state-changing operations.
    function pause() external onlyOwner { _pause(); }

    /// @notice Unpause all operations.
    function unpause() external onlyOwner { _unpause(); }
}
