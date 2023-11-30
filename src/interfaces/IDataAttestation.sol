// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title IDataAttestation
/// @notice EZKL Data Attestation contract interface to verify DA + proof
/// @dev Uses: https://docs.ezkl.xyz/visibility_what_is_private/#data-provenance-signatures-and-linking-data
interface IDataAttestation {
    /// @notice Verifies inputs against contract, verifies proof
    /// @param verifier EZKL verifier address
    /// @param encoded DA + proof data
    /// @return success status
    function verifyWithDataAttestation(address verifier, bytes calldata encoded) external view returns (bool);
}
