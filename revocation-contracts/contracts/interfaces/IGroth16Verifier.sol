// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IGroth16Verifier
 * @notice Interface for a Groth16 zk-SNARK verifier over the BN254 curve.
 *         The parameter layout is identical to the output of
 *         `snarkjs generatesolidity` / `snarkjs exportsoliditycalldata`.
 *
 * Coordinate conventions (EIP-197 / SnarkJS):
 *   _pA  : G1 point  [x, y]
 *   _pB  : G2 point  [[x_im, x_re], [y_im, y_re]]  (imaginary part first)
 *   _pC  : G1 point  [x, y]
 *   _pubSignals : array of public inputs (Fp elements)
 */
interface IGroth16Verifier {
    /**
     * @notice Verifies a Groth16 proof.
     * @param _pA        Proof element A (G1 point).
     * @param _pB        Proof element B (G2 point).
     * @param _pC        Proof element C (G1 point).
     * @param _pubSignals Public inputs/outputs of the circuit.
     * @return           True if the proof is valid, false otherwise.
     */
    function verifyProof(
        uint256[2]    calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2]    calldata _pC,
        uint256[1]    calldata _pubSignals
    ) external view returns (bool);
}
