// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Ownable} from "solady/auth/Ownable.sol";

/// @title Configured
/// @notice Allows storing and updating global contract configuration parameters
/// @dev `_initializeConfig()` must be called at contract creation
abstract contract Configured is Ownable {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Config represents global Frenrug configuration parameters
    /// @dev Tightly-packed struct:
    ///      - [attestor, nodes, maxCallbackGasLimit]: [160, 16, 32] = 208
    ///      - [verifier]: [160] = 160
    struct Config {
        /// @notice Address for the EZKL Data Attestation contract (summarizer model)
        address attestor;
        /// @notice Number of node responses required before kicking off summarizer model request
        /// @dev To prevent re-triggering completed summarizations (increase count, resubmit signed message) prefer to only decrease this count
        uint16 nodes;
        /// @notice Maximum gas limit in wei for summarizer model callback
        /// @dev Can change dynamically to account for changes to model verifier
        uint32 maxCallbackGasLimit;
        /// @notice Address for the EZKL Proof Verification contract (summarizer model)
        address verifier;
        /// @notice Summarizer Infernet container IDs
        string containerId;
    }

    /*//////////////////////////////////////////////////////////////
                                MUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Global configuration parameters
    Config public config;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when contract config is updated
    /// @param newConfig new config
    event ConfigUpdated(Config newConfig);

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates global config
    /// @dev Must be called at contract creation
    /// @param newConfig new config to set
    function _updateConfig(Config memory newConfig) internal {
        config = newConfig;
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Allows owner to update global config
    /// @param newConfig new config to update
    function updateConfig(Config calldata newConfig) external onlyOwner {
        _updateConfig(newConfig);

        // Emit change
        emit ConfigUpdated(newConfig);
    }
}
