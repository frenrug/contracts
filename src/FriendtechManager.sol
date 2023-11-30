// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Ownable} from "solady/auth/Ownable.sol";
import {IFriendtechSharesV1} from "./interfaces/IFriendtechSharesV1.sol";

/// @title FriendtechManager
/// @notice Manages interfacing with the FriendtechSharesV1 contract
abstract contract FriendtechManager is Ownable {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Possible reasons for a messages' execution to fail
    enum ExecutionFailure {
        None, // No failure
        InsufficientFunds, // Bot does not have enough ETH to buy key
        KeyNotActive, // Key owner has yet to purchase their first key
        KeyNotOwned, // Bot does not own key which is trying to be sold
        LastKeyLeft, // Bot cannot sell the last key
        Unknown // Unknown error (value transfer failure)
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown from FriendtechSharesV1 if trying to buy inactive key
    bytes32 private constant KEY_NOT_ACTIVE_ERROR = keccak256(bytes("Only the shares' subject can buy the first share"));

    /// @notice Error thrown from FriendtechSharesV1 if trying to sell key without owning it
    bytes32 private constant INSUFFICIENT_KEYS_OWNED_ERROR = keccak256(bytes("Insufficient shares"));

    /// @notice Error thrown from FriendtechSharesV1 if trying to sell last key
    bytes32 private constant CANNOT_SELL_LAST_KEY_ERROR = keccak256(bytes("Cannot sell the last share"));

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice FriendtechSharesV1 contract
    IFriendtechSharesV1 private immutable FRIENDTECH;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// Create new FriendtechOperator
    /// @param _friendtech FriendtechSharesV1 address
    constructor(address _friendtech) {
        // Initialize friendtech interface
        FRIENDTECH = IFriendtechSharesV1(_friendtech);
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attempts to buy a key
    /// @param key key address to purchase
    /// @return execution failure
    function buyKey(address key) internal returns (ExecutionFailure) {
        // Calculate price to buy key
        uint256 price = FRIENDTECH.getBuyPriceAfterFee(key, 1);

        // If insufficient balance, return `InsufficientFunds`
        if (address(this).balance < price) {
            return ExecutionFailure.InsufficientFunds;
        }

        // Attempt to purchase key
        try FRIENDTECH.buyShares{value: price}(key, 1) {
            // If successful, return no failure
            return ExecutionFailure.None;
        } catch Error(string memory reason) {
            // Check if key is inactive and throw
            if (keccak256(bytes(reason)) == KEY_NOT_ACTIVE_ERROR) {
                return ExecutionFailure.KeyNotActive;
            }

            // Else, return unknown error
            return ExecutionFailure.Unknown;
        }
    }

    /// @notice Attempts to sell a key
    /// @param key key address to sell
    /// @return execution failure
    function sellKey(address key) internal returns (ExecutionFailure) {
        // Attempt to sell key
        try FRIENDTECH.sellShares(key, 1) {
            // If successful, return no failure
            return ExecutionFailure.None;
        } catch Error(string memory reason) {
            bytes32 reasonHash = keccak256(bytes(reason));

            // Throw if attempting to sell last key
            if (reasonHash == CANNOT_SELL_LAST_KEY_ERROR) {
                return ExecutionFailure.LastKeyLeft;
            }

            // Throw if attempting to sell unowned key
            if (reasonHash == INSUFFICIENT_KEYS_OWNED_ERROR) {
                return ExecutionFailure.KeyNotOwned;
            }

            // Else, return unknown error
            return ExecutionFailure.Unknown;
        }
    }

    /// @notice Allows owner to directly sell key
    /// @param key key address to sell
    function ownerSellKey(address key) external onlyOwner {
        FRIENDTECH.sellShares(key, 1);
    }
}
