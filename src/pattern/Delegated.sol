// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Ownable} from "solady/auth/Ownable.sol";
import {Delegator} from "infernet/pattern/Delegator.sol";

/// @title Delegated
/// @notice Allows delegating Infernet-compatible EIP-712 signer
/// @notice Exposes `onlyOwner`-permissioned `updateDelegatee()` function to update EIP-712 signer
/// @dev Defaults to delegating to msg.sender
abstract contract Delegated is Ownable, Delegator {
    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Create new Delegated
    /// @dev Initializes delegatee signer to msg.sender
    constructor() Delegator(msg.sender) {}

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Allows owner to update delegatee signer
    /// @param signer new signer to update
    function updateDelegatee(address signer) external onlyOwner {
        _updateSigner(signer);
    }
}
