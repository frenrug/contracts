// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {console} from "forge-std/console.sol";
import {Frenrug} from "../src/Frenrug.sol";
import {Script} from "forge-std/Script.sol";
import {Configured} from "../src/pattern/Configured.sol";

contract UpdateVerifier is Script {
    function run() public {
        // Setup wallet
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Load up Frenrug contract
        Configured FRENRUG = Configured(payable(0x...));

        // Collect current params
        (address attestor, uint16 nodes, uint32 maxCallbackGasLimit, address verifier, string memory containerId) = FRENRUG.config();
        console.log(attestor);
        console.log(nodes);
        console.log(maxCallbackGasLimit);
        console.log(verifier);
        console.log(containerId);

        // Update just new verifier
        Configured.Config memory newConfig = Configured.Config({
            attestor: attestor,
            nodes: nodes,
            maxCallbackGasLimit: maxCallbackGasLimit,
            verifier: 0x...,
            containerId: containerId
        });

        // Update config
        FRENRUG.updateConfig(newConfig);

        vm.stopBroadcast();
    }
}
