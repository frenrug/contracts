// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {FrenrugTest} from "./Frenrug.t.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/// @title DelegatedTest
/// @notice Tests isolated `Delegated.sol` functionality
contract DelelegatedTest is FrenrugTest {
    /// @notice Delegatee is properly initialized
    function testDelegateeIsProperlyInitialized() public {
        assertEq(FRENRUG.signer(), DELEGATEE_ADDRESS);
    }

    /// @notice Delegatee can be updated by owner
    function testOwnerCanUpdateDelegatee() public {
        // Assert initial
        assertEq(FRENRUG.signer(), DELEGATEE_ADDRESS);

        // Update delegatee
        FRENRUG.updateDelegatee(address(1));

        // Assert new
        assertEq(FRENRUG.signer(), address(1));
    }

    /// @notice Delegatee cannot be updated by non-owner
    function testNonOwnerCannotUpdatedDelegatee() public {
        // Mock non-owner
        vm.startPrank(address(1));

        // Attempt to update delegatee
        vm.expectRevert(Ownable.Unauthorized.selector);
        FRENRUG.updateDelegatee(address(1));
    }
}
