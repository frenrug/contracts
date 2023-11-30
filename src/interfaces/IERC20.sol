// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title IERC20
/// @notice Basic ERC20-compliant token interface
interface IERC20 {
    /// @notice Returns the amount of tokens owned by `account`
    /// @param account address to check
    /// @return balance of `account`
    function balanceOf(address account) external view returns (uint256);

    /// @notice Moves a `value` amount of tokens from the caller's account to the `to` account
    /// @param to address to move tokens to
    /// @param value amount of tokens to move
    /// @return successful transfer status
    function transfer(address to, uint256 value) external returns (bool);
}
