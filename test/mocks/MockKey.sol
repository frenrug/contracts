// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {FriendtechSharesV1} from "../interfaces/FriendtechSharesV1.sol";

/// @title MockKey
/// @notice Mocks the functionality of a Friendtech Key account
/// @dev Friend.tech keys have royalties / need inbound payment, thus cannot mock a random address
contract MockKey {
    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice FriendtechSharesV1
    FriendtechSharesV1 internal FRIENDTECH;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// Creates new MockKey
    /// @param _friendtech Friendtech
    constructor(FriendtechSharesV1 _friendtech) {
        FRIENDTECH = _friendtech;
    }

    /*//////////////////////////////////////////////////////////////
                           UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Buys Friendtech key for account
    function buyKey() external {
        uint256 price = FRIENDTECH.getBuyPriceAfterFee(address(this), 1);
        FRIENDTECH.buyShares{value: price}(address(this), 1);
    }

    /// @notice Sells Friendtech key for account
    function sellKey() external {
        FRIENDTECH.sellShares(address(this), 1);
    }

    /// @notice Required to enable royalties + key sales
    receive() external payable {}
}
