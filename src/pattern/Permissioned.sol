// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Configured} from "./Configured.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/// @title Permissioned
/// @notice Exposes interface to restrict subscription-fulfillment to permissioned set of nodes
/// @dev Should be initialized after global Config (via Configured) is initialized (could be restricted via modifier, but unnecessary for now)
/// @dev Useful when requesting a subset of Infernet network with private containers to respond
/// @dev Useful when initiating subscription requests off-chain w/ redundancy > 1
/// @dev Useful when using containers that do not supply a succinct proof
abstract contract Permissioned is Ownable, Configured {
    /*//////////////////////////////////////////////////////////////
                                MUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice List of nodes with permission to respond to subscriptions
    mapping(address => bool) public allowedNodes;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown if attempting to call an `onlyPermissionedNode()` function as a non-permissioned node
    /// @dev 4-byte signature: `0xd65548b9`
    error NotPermissionedNode();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Only nodes on the permissioned allowlist
    /// @dev msg.sender in callbacks is always address(Coordinator), thus we must explicitly check against node address
    /// @param node address to check
    modifier onlyPermissionedNode(address node) {
        if (!allowedNodes[node]) {
            revert NotPermissionedNode();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Allows updating allowlist
    /// @dev Does not perform any checks against `config.nodes` to ensure allowed redundany count
    /// @dev Does not perform any checks to ensure `nodes.length == status.length`
    /// @dev Does not perform any checks to ensure that you are not redundantly updating status (false to false, etc.)
    /// @param nodes node addresses to update
    /// @param status node statuses
    function _updateAllowlist(address[] memory nodes, bool[] memory status) internal {
        for (uint256 i = 0; i < nodes.length; i++) {
            allowedNodes[nodes[i]] = status[i];
        }
    }

    /// @notice Allows owner to update allowlist
    function updateAllowlist(address[] memory nodes, bool[] memory status) external onlyOwner {
        _updateAllowlist(nodes, status);
    }
}
