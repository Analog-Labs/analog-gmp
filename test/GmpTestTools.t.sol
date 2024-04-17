// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Example.t.sol)

pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import {Gateway, GatewayEIP712} from "src/Gateway.sol";
import {GatewayProxy} from "src/GatewayProxy.sol";
import {IGateway} from "src/interfaces/IGateway.sol";
import {IExecutor} from "src/interfaces/IExecutor.sol";
import {GmpMessage, PrimitivesEip712} from "src/Primitives.sol";
import {MockERC20} from "src/examples/MockERC20.sol";
import {TestUtils} from "./TestUtils.sol";
import {GmpTestTools} from "./GmpTestTools.sol";

contract GmpTestToolsTest is Test {
    using PrimitivesEip712 for GmpMessage;
    using TestUtils for address;

    address private constant ALICE = address(bytes20(keccak256("Alice")));
    address private constant BOB = address(bytes20(keccak256("Bob")));

    Gateway private constant SEPOLIA_GATEWAY = Gateway(GmpTestTools.ETHEREUM_SEPOLIA);
    uint16 private constant SEPOLIA_NETWORK = GmpTestTools.ETHEREUM_SEPOLIA_ID;

    Gateway private constant SHIBUYA_GATEWAY = Gateway(GmpTestTools.ASTAR_SHIBUYA);
    uint16 private constant SHIBUYA_NETWORK = GmpTestTools.ASTAR_SHIBUYA_ID;

    /// @dev Test the teleport of tokens from Alice's account in Sepolia to Alice's account in Shibuya
    function testTeleportAliceTokens() external {
        ////////////////////////////////////
        // Step 1: Setup test environment //
        ////////////////////////////////////

        // Deploy the gateway contracts at pre-defined addresses
        // Also creates one fork for each supported network
        GmpTestTools.setup();

        // Add funds to Alice account in all networks
        GmpTestTools.deal(ALICE, 100 ether);
        GmpTestTools.deal(BOB, 100 ether);

        ///////////////////////////////////////////////////////
        // Step 2: Deploy the sender and recipient contracts //
        ///////////////////////////////////////////////////////

        // Pre-compute the contract addresses, because the contracts must know each other addresses.
        MockERC20 shibuyaErc20 = MockERC20(vm.computeCreateAddress(ALICE, vm.getNonce(ALICE)));
        MockERC20 sepoliaErc20 = MockERC20(vm.computeCreateAddress(BOB, vm.getNonce(BOB)));

        // Switch to Shibuya network and Alice account, then deploy the ERC20 contract
        GmpTestTools.switchNetwork(SHIBUYA_NETWORK, ALICE);
        shibuyaErc20 = new MockERC20("Shibuya ", "A", SHIBUYA_GATEWAY, sepoliaErc20, SEPOLIA_NETWORK, ALICE, 1000);
        assertEq(shibuyaErc20.balanceOf(ALICE), 1000, "unexpected alice balance in shibuya");
        assertEq(shibuyaErc20.balanceOf(BOB), 0, "unexpected bob balance in shibuya");

        // Switch to Sepolia network and Bob account, then deploy the ERC20 contract
        GmpTestTools.switchNetwork(SEPOLIA_NETWORK, BOB);
        sepoliaErc20 = new MockERC20("Sepolia", "B", SEPOLIA_GATEWAY, shibuyaErc20, SHIBUYA_NETWORK, BOB, 0);
        assertEq(sepoliaErc20.balanceOf(ALICE), 0, "unexpected alice balance in sepolia");
        assertEq(sepoliaErc20.balanceOf(BOB), 0, "unexpected bob balance in sepolia");

        // Check if the computed addresses matches
        assertEq(address(shibuyaErc20), vm.computeCreateAddress(ALICE, 0), "unexpected sepoliaErc20 address");
        assertEq(address(sepoliaErc20), vm.computeCreateAddress(BOB, 0), "unexpected sepoliaErc20 address");

        ///////////////////////////////////////////////////////////
        // Step 3: Deposit funds to destination Gateway Contract //
        ///////////////////////////////////////////////////////////
        // Switch to Sepolia network and Alice account
        GmpTestTools.switchNetwork(SEPOLIA_NETWORK, ALICE);
        // If the sender is a contract, it's address must be converted
        bytes32 source = TestUtils.source(address(shibuyaErc20), true);
        // Alice deposit 1 ether to Sepolia gateway contract
        SEPOLIA_GATEWAY.deposit{value: 1 ether}(source, SHIBUYA_NETWORK);

        //////////////////////////////
        // Step 4: Send GMP message //
        //////////////////////////////
        // Switch to Shibuya network and Alice account
        GmpTestTools.switchNetwork(SHIBUYA_NETWORK, ALICE);

        // Teleport 100 tokens from Alice's account in shibuya to Bob's account in sepolia
        // Obs: The `teleport` method internally calls `gateway.submitMessage(...)`
        bytes32 messageID = shibuyaErc20.teleport(BOB, 100);

        // Now with the `messageID`, Alice can check if for the message status in the destination gateway contract
        // status 0: means the message is pending
        // status 1: means the message was executed successfully
        // status 2: means the message was executed but reverted
        GmpTestTools.switchNetwork(SEPOLIA_NETWORK, ALICE);
        assertTrue(SEPOLIA_GATEWAY.gmpInfo(messageID).status == 0, "unexpected message status, expect 'pending'");

        ///////////////////////////////////////////////////
        // Step 5: Wait Chronicles Relay the GMP message //
        ///////////////////////////////////////////////////
        // The GMP hasn't been executed yet...
        assertEq(sepoliaErc20.balanceOf(ALICE), 0, "unexpected alice balance in shibuya");

        // Note: In the real world, the GMP message would be relayed by Chronicle Nodes, and they wait for a minimum number of
        // confirmations before relay the message. In this test, we will simulate the relay by calling `GmpTestTools.flushPendingMessages()`,
        // this will relay all pending messages in the same order they were created.
        GmpTestTools.flushPendingMessages();

        // Success! The GMP message has been executed!!!
        assertTrue(SEPOLIA_GATEWAY.gmpInfo(messageID).status == 1, "failed to execute GMP");

        // Check ALICE and BOB balance in shibuya
        GmpTestTools.switchNetwork(SHIBUYA_NETWORK);
        assertEq(shibuyaErc20.balanceOf(ALICE), 900, "unexpected alice's balance in shibuya");
        assertEq(shibuyaErc20.balanceOf(BOB), 0, "unexpected bob's balance in shibuya");

        // Check ALICE and BOB balance in sepolia
        GmpTestTools.switchNetwork(SEPOLIA_NETWORK);
        assertEq(sepoliaErc20.balanceOf(ALICE), 0, "unexpected alice's balance in sepolia");
        assertEq(sepoliaErc20.balanceOf(BOB), 100, "unexpected bob's balance in sepolia");
    }
}
