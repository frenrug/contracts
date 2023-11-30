// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title IFriendtechSharesV1
/// @notice FriendtechSharesV1 contract interface to buy & sell keys
/// @dev Source: https://basescan.org/address/0xcf205808ed36593aa40a44f10c7f7c2f67d4a4d4#code
interface IFriendtechSharesV1 {
    /// @notice Buy Friendtech keys
    /// @param sharesSubject key address
    /// @param amount number of keys to purchase
    function buyShares(address sharesSubject, uint256 amount) external payable;

    /// @notice Sell Friendtech keys
    /// @param sharesSubject key address
    /// @param amount number of keys to sell
    function sellShares(address sharesSubject, uint256 amount) external payable;

    /// @notice Collect price in ETH to purchase `amount` of `sharesSubject`'s keys
    /// @param sharesSubject key address
    /// @param amount number of keys to purchase
    function getBuyPriceAfterFee(address sharesSubject, uint256 amount) external view returns (uint256);
}
