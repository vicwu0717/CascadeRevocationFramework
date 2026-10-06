// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../interfaces/IGroth16Verifier.sol";

/**
 * @title MockVerifier
 * @notice Test-only Groth16 verifier whose return value can be toggled
 *         by the deployer.  Never deploy on a live network.
 */
contract MockVerifier is IGroth16Verifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    /// @notice Allow tests to flip the verifier result at runtime.
    function setShouldPass(bool _val) external {
        shouldPass = _val;
    }

    function verifyProof(
        uint256[2]    calldata,
        uint256[2][2] calldata,
        uint256[2]    calldata,
        uint256[1]    calldata
    ) external view override returns (bool) {
        return shouldPass;
    }
}
