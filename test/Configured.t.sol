// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {FrenrugTest} from "./Frenrug.t.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Configured} from "../src/pattern/Configured.sol";

/// @title ConfiguredTest
/// @notice Tests isolated `Configured.sol` functionality
contract ConfiguredTest is FrenrugTest {
    /// @notice Configuration is correctly set at deploy
    function testConfigurationSetCorrectly() public {
        (address attestor, uint16 nodes, uint32 maxCallbackGasLimit, address verifier, string memory containerId) =
            FRENRUG.config();

        // Assert params
        assertEq(attestor, address(ATTESTOR));
        assertEq(nodes, 3);
        assertEq(maxCallbackGasLimit, 10_000_000 wei);
        assertEq(verifier, VERIFIER_ADDRESS);
        assertEq(containerId, "inference,proving");
    }

    /// @notice Configuration can be updated
    function testConfigurationCanBeUpdated() public {
        // Setup new config with old parameters + new container ID
        (address attestor, uint16 nodes, uint32 maxCallbackGasLimit, address verifier, string memory containerId) =
            FRENRUG.config();

        string memory newContainerId = "new-container-id";
        Configured.Config memory newConfig = Configured.Config({
            attestor: attestor,
            nodes: nodes,
            maxCallbackGasLimit: maxCallbackGasLimit,
            verifier: verifier,
            containerId: newContainerId
        });

        // Update config and expect emit
        vm.expectEmit(address(FRENRUG));
        emit ConfigUpdated(newConfig);
        FRENRUG.updateConfig(newConfig);

        // Assert new params
        (attestor, nodes, maxCallbackGasLimit, verifier, containerId) = FRENRUG.config();
        assertEq(attestor, address(ATTESTOR));
        assertEq(nodes, 3);
        assertEq(maxCallbackGasLimit, 10_000_000 wei);
        assertEq(verifier, VERIFIER_ADDRESS);
        assertEq(containerId, newContainerId);
    }

    /// @notice Configuration cannot be updated by non-owner
    function testNonOwnerCannotUpdateConfiguration() public {
        // Setup new dummy configuration
        Configured.Config memory newConfig = Configured.Config({
            attestor: address(0),
            nodes: 0,
            maxCallbackGasLimit: 0 wei,
            verifier: address(0),
            containerId: ""
        });

        // Mock non-owner
        vm.startPrank(address(1));

        // Attempt to update configuration
        vm.expectRevert(Ownable.Unauthorized.selector);
        FRENRUG.updateConfig(newConfig);
    }
}
