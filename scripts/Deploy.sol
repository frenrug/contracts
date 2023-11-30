// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Frenrug} from "../src/Frenrug.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {DataAttestation} from "../test/DataAttestor.sol";
import {Configured} from "../src/pattern/Configured.sol";
import {EIP712Coordinator} from "infernet/EIP712Coordinator.sol";

contract Deploy is Script {
    function run() public {
        // Setup wallet
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Log address
        address deployerAddress = vm.addr(deployerPrivateKey);
        console.log("Deployer address: ", deployerAddress);

        // Log coordinator
        address COORDINATOR = 0x...;
        console.log("Coordinator address: ", COORDINATOR);

        // Setup input parameters for attestor contract
        // Contract address to staticcall (our consumer contract, in this case, address(FRENRUG))
        address frenrugAddress = 0x...;
        address[] memory _contractAddresses = new address[](2);
        _contractAddresses[0] = frenrugAddress;
        _contractAddresses[1] = frenrugAddress;

        // Function calldata to get int256[1] input parameters
        bytes[][] memory _calldata = new bytes[][](2);
        _calldata[0] = new bytes[](1);
        _calldata[1] = new bytes[](1);
        // We expose the current int256[1] parameters via Frenrug.currentData
        // We can simply encode the getter function for this public int256[1] state
        bytes4 GETTER_SELECTOR = bytes4(keccak256("attestedInputs(uint256)"));
        _calldata[0][0] = abi.encodeWithSelector(GETTER_SELECTOR, 0);
        _calldata[1][0] = abi.encodeWithSelector(GETTER_SELECTOR, 1);

        // Decimals and scaling are default set to 0
        uint256[][] memory _decimals = new uint256[][](2);
        _decimals[0] = new uint256[](1);
        _decimals[1] = new uint256[](1);
        _decimals[0][0] = 0;
        _decimals[1][0] = 0;
        uint256[] memory _scales = new uint256[](2);
        _scales[0] = 0;
        _scales[1] = 0;

        // Initialize new attestor contract
        DataAttestation ATTESTOR = new DataAttestation(
            _contractAddresses,
            _calldata,
            _decimals,
            _scales,
            0,
            deployerAddress
        );
        console.log("Attestor address: ", address(ATTESTOR));

        // Verifier contract
        address VERIFIER = 0x...;
        console.log("Verifier address: ", VERIFIER);

        // Frenrug contract setup
        Configured.Config memory config = Configured.Config({
            attestor: address(ATTESTOR),
            nodes: 3,
            maxCallbackGasLimit: 3_000_000 wei,
            verifier: address(VERIFIER),
            containerId: "56bee1d5a6ab406e366c76f5ad2444c32c9d96539945b34f8ce3ba7c05c2e2ae"
        });
        address friendTechSharesV1 = 0xCF205808Ed36593aa40a44F10c7f7C2F67d4A4d4;
        address[] memory allowedNodes = new address[](3);
        allowedNodes[0] = 0x...;
        allowedNodes[1] = 0x...;
        allowedNodes[2] = 0x...;
        bool[] memory status = new bool[](3);
        status[0] = true;
        status[1] = true;
        status[2] = true;
        Frenrug FRENRUG = new Frenrug(
            config,
            friendTechSharesV1,
            COORDINATOR,
            allowedNodes,
            status
        );
        console.log("Frenrug address: ", address(FRENRUG));

        // Update frenrug delegated address
        FRENRUG.updateDelegatee(0x...);

        vm.stopBroadcast();
    }
}
