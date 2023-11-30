// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {IERC20} from "../interfaces/IERC20.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/// @title Banked
/// @notice Provides contract owner with ETH, ERC20 management functionality
/// @dev Requires inheriting contract to call `_initializeOwner()` to initialize ownership
/// @dev Allows withdrawing arbitrary token balances
/// @dev Allows emptying contract ETH balance
/// @dev Exposes payable receive function to allow inheriting contracts to receive ETH
abstract contract Banked is Ownable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown if ETH transfer fails to succeed
    /// @dev 4-byte signature: `0x90b8ec18`
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Allows owner to withdraw ETH balance
    function withdrawBalance() external onlyOwner {
        // Attempt to transfer ETH balance of contract to owner
        (bool success,) = msg.sender.call{value: address(this).balance}("");

        // Revert if not successful
        if (!success) {
            revert TransferFailed();
        }
    }

    /// @notice Allows owner to withdraw arbitrary ERC20 token balances
    /// @param tokenAddress token contract address
    function withdrawTokenBalance(address tokenAddress) external onlyOwner {
        // Setup token
        IERC20 token = IERC20(tokenAddress);

        // Get balance of this address in token
        uint256 balance = token.balanceOf(address(this));

        // Send token balance to caller (owner)
        token.transfer(msg.sender, balance);
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
