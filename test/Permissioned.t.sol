// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {FrenrugTest} from "./Frenrug.t.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Coordinator} from "infernet/Coordinator.sol";
import {Permissioned} from "../src/pattern/Permissioned.sol";

/// @title PermissionedTest
/// @notice Tests isolated `Permissioned.sol` functionality
contract PermissionedTest is FrenrugTest {
    /// @notice Allow list is correctly initialized
    function testAllowlistIsCorrectlyInitialized() public {
        assertTrue(FRENRUG.allowedNodes(address(ALICE)));
        assertTrue(FRENRUG.allowedNodes(address(BOB)));
        assertTrue(FRENRUG.allowedNodes(address(CHARLIE)));
    }

    /// @notice Owner can update allow list and new node can respond
    function testOwnerCanUpdateAllowlistAndNewNodeCanRespond() public {
        // Add David to the mix as an allowed node
        address DAVID = address(8);
        address[] memory nodes = new address[](1);
        bool[] memory status = new bool[](1);
        nodes[0] = DAVID;
        status[0] = true;
        FRENRUG.updateAllowlist(nodes, status);
        assertTrue(FRENRUG.allowedNodes(DAVID));

        // Mock calls as David
        vm.startPrank(DAVID);

        // Register David as node
        vm.warp(0);
        COORDINATOR.registerNode(DAVID);
        vm.warp(COORDINATOR.cooldown());
        COORDINATOR.activateNode();

        // Deliver subscription
        (
            uint32 nonce,
            uint32 expiry,
            Coordinator.Subscription memory subscription,
            uint8 v,
            bytes32 r,
            bytes32 s,
            uint32 interval,
            bytes memory input,
            bytes memory output,
            bytes memory proof
        ) = getMockLLMResponse(0);
        COORDINATOR.deliverComputeDelegatee(nonce, expiry, subscription, v, r, s, interval, input, output, proof);
    }

    /// @notice Owner can update allow list and removed node can no longer respond
    function testOwnerCanUpdateAllowlistAndRemovedNodeCannotRespond() public {
        // Remove Charlie from allowlist
        assertTrue(FRENRUG.allowedNodes(address(CHARLIE)));
        address[] memory nodes = new address[](1);
        bool[] memory status = new bool[](1);
        nodes[0] = address(CHARLIE);
        status[0] = false;
        FRENRUG.updateAllowlist(nodes, status);
        assertFalse(FRENRUG.allowedNodes(address(CHARLIE)));

        // Attempt to deliver output from Charlie
        (
            uint32 nonce,
            uint32 expiry,
            Coordinator.Subscription memory subscription,
            uint8 v,
            bytes32 r,
            bytes32 s,
            uint32 interval,
            bytes memory input,
            bytes memory output,
            bytes memory proof
        ) = getMockLLMResponse(0);
        vm.expectRevert(Permissioned.NotPermissionedNode.selector);
        CHARLIE.deliverComputeDelegatee(nonce, expiry, subscription, v, r, s, interval, input, output, proof);
    }

    /// @notice Non-owner cannot update allowlist
    function testNonOwnerCannotUpdateAllowlist() public {
        // Mock non-owner
        vm.startPrank(address(1));

        // Attempt to update allowlist
        address[] memory nodes = new address[](0);
        bool[] memory status = new bool[](0);
        vm.expectRevert(Ownable.Unauthorized.selector);
        FRENRUG.updateAllowlist(nodes, status);
    }
}
