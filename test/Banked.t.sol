// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {FrenrugTest} from "./Frenrug.t.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Banked} from "../src/pattern/Banked.sol";
import {MockERC20} from "solady-tests/utils/mocks/MockERC20.sol";

/// @title BankedTest
/// @notice Tests isolated `Banked.sol` functionality
contract BankedTest is FrenrugTest {
    /// @notice Can transfer ETH to contract
    function testCanTransferETHToContract() public {
        // Assert no starting balance
        assertEq(address(FRENRUG).balance, 0 ether);

        // Transfer in 1 ETH
        payable(FRENRUG).transfer(1 ether);

        // Assert balance
        assertEq(address(FRENRUG).balance, 1 ether);
    }

    /// @notice Owner can withdraw ETH from contract
    function testOwnerCanWithdrawETHFromContract() public {
        // Transfer in ETH
        uint256 startBalance = address(this).balance;
        payable(FRENRUG).transfer(1 ether);
        uint256 endBalance = address(this).balance;
        assertEq(address(FRENRUG).balance, 1 ether);
        assertEq(startBalance - 1 ether, endBalance);

        // Attempt to withdraw
        FRENRUG.withdrawBalance();
        assertEq(address(FRENRUG).balance, 0 ether);
        assertEq(address(this).balance, startBalance);
    }

    /// @notice Non-owner cannot withdraw ETH from contract
    function testNonOwnerCannotWithdrawETHFromContract() public {
        // Mock non-owner
        vm.startPrank(address(1));

        // Attempt to withdraw balance
        vm.expectRevert(Ownable.Unauthorized.selector);
        FRENRUG.withdrawBalance();
    }

    /// @notice Owner can withdraw ERC20 tokens
    function testOwnerCanWithdrawERC20Tokens() public {
        // Create token
        MockERC20 token = new MockERC20("", "", 18);

        // Assert current balances
        assertEq(token.balanceOf(address(this)), 0);
        assertEq(token.balanceOf(address(FRENRUG)), 0);

        // Mint 5 tokens to Frenrug
        token.mint(address(FRENRUG), 5e18);
        assertEq(token.balanceOf(address(FRENRUG)), 5e18);

        // Attempt to withdraw
        FRENRUG.withdrawTokenBalance(address(token));
        assertEq(token.balanceOf(address(this)), 5e18);
        assertEq(token.balanceOf(address(FRENRUG)), 0);
    }

    /// @notice Non-owner cannot withdraw ERC20 tokens
    function testNonOwnerCannotWithdrawERC20Tokens() public {
        // Create token
        MockERC20 token = new MockERC20("", "", 18);

        // Assert current balances
        assertEq(token.balanceOf(address(this)), 0);
        assertEq(token.balanceOf(address(FRENRUG)), 0);

        // Mint 5 tokens to Frenrug
        token.mint(address(FRENRUG), 5e18);
        assertEq(token.balanceOf(address(FRENRUG)), 5e18);

        // Mock non-owner
        vm.startPrank(address(1));

        // Attempt to withdraw
        vm.expectRevert(Ownable.Unauthorized.selector);
        FRENRUG.withdrawTokenBalance(address(token));
    }

    receive() external payable {}
}

/// @title BankedNoReceiverTest
/// @notice Tests isolated `Banked.sol` ETH transfer functionality to non-receiver
contract BankedNoReceiverTest is FrenrugTest {
    /// @notice ETH transfer fails if transferring to a non-receiver contract
    function testETHTransferFailsIfTransferringToNonReceiver() public {
        // Transfer in 1 ETH
        payable(FRENRUG).transfer(1 ether);

        // Attempt to withdraw balance
        vm.expectRevert(Banked.TransferFailed.selector);
        FRENRUG.withdrawBalance();
    }
}
