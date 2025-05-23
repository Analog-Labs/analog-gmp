// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Gateway.t.sol)

pragma solidity >=0.8.0;

import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "./TestUtils.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {GasUtils} from "../src/utils/GasUtils.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {UFloat9x56, UFloatMath} from "../src/utils/Float9x56.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {IExecutor} from "../src/interfaces/IExecutor.sol";
import {
    GmpMessage,
    UpdateKeysMessage,
    Signature,
    TssKey,
    Network,
    GmpCallback,
    GmpStatus,
    PrimitiveUtils,
    GmpSender,
    GMP_VERSION
} from "../src/Primitives.sol";

contract SigUtilsTest is GatewayEIP712, Test {
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpCallback;

    constructor() GatewayEIP712(69, address(0)) {}

    function testPayload() public pure {
        GmpMessage memory gmp = GmpMessage({
            source: GmpSender.wrap(bytes32(uint256(1))),
            srcNetwork: 42,
            dest: address(0x1),
            destNetwork: 69,
            gasLimit: 0,
            nonce: 2,
            data: "42"
        });
        GmpCallback memory callback = gmp.memToCallback();

        bytes32 msgId = keccak256(
            abi.encode(
                GMP_VERSION,
                gmp.source,
                gmp.srcNetwork,
                gmp.dest,
                gmp.destNetwork,
                gmp.gasLimit,
                gmp.nonce
            )
        );

        assertEq(gmp.messageId(), msgId);
        assertEq(callback.messageId(), msgId);

        bytes32 dataHash = keccak256(gmp.data);
        bytes32 opHash = keccak256(abi.encode(msgId, dataHash));
        assertEq(opHash, gmp.opHash());
        assertEq(opHash, callback.opHash);
    }
}

// contract GatewayBase is Test {
contract GatewayTest is Test {
    using PrimitiveUtils for UpdateKeysMessage;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpSender;
    using PrimitiveUtils for address;
    using BranchlessMath for uint256;

    Gateway internal gateway;

    // Chronicle TSS Secret
    uint256 private constant SECRET = 0x42;
    uint256 private constant SIGNING_NONCE = 0x69;

    // Receiver Contract, the will waste the exact amount of gas you sent to it in the data field
    IGmpReceiver internal receiver;

    // Netowrk ids
    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;

    address internal constant ADMIN = 0x6f4c950442e1Af093BcfF730381E63Ae9171b87a;

    constructor() {
        VmSafe.Wallet memory admin = vm.createWallet(SECRET);
        assertEq(ADMIN, admin.addr, "admin address mismatch");
        gateway = Gateway(
            payable(address(TestUtils.setupGateway(admin, DEST_NETWORK_ID)))
        );
        TestUtils.setMockShard(admin, address(gateway), admin);
        TestUtils.setMockRoute(admin, address(gateway), DEST_NETWORK_ID);
        receiver = IGmpReceiver(new GasSpender());
    }

    function setUp() external view {
        // check block gas limit as gas left
        assertEq(block.gaslimit, 30_000_000);
        assertTrue(gasleft() >= 10_000_000);
    }

    function sign(GmpMessage memory gmp) internal returns (Signature memory) {
        bytes32 hash = gmp.opHash();
        Signer signer = new Signer(SECRET);
        (uint256 e, uint256 s) = signer.signPrehashed(uint256(hash), SIGNING_NONCE);
        return Signature({xCoord: signer.xCoord(), e: e, s: s});
    }

    function _sortTssKeys(TssKey[] memory keys) private pure {
        // sort keys by xCoord
        for (uint256 i = 0; i < keys.length; i++) {
            for (uint256 j = i + 1; j < keys.length; j++) {
                if (keys[i].xCoord > keys[j].xCoord) {
                    TssKey memory temp = keys[i];
                    keys[i] = keys[j];
                    keys[j] = temp;
                }
            }
        }
    }

    function test_setShards() external {
        TssKey[] memory keys = new TssKey[](10);

        // create random shard keys
        Signer signer;
        for (uint256 i = 0; i < keys.length; i++) {
            signer = new Signer(i + 1);
            keys[i] = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        }
        _sortTssKeys(keys);

        // Only admin can set shards keys
        vm.expectRevert("unauthorized");
        gateway.setShards(keys);

        // Set shards keys must work
        vm.prank(ADMIN, ADMIN);
        gateway.setShards(keys);

        // Check shards keys
        TssKey[] memory shards = gateway.shards();
        _sortTssKeys(shards);
        for (uint256 i = 0; i < shards.length; i++) {
            assertEq(shards[i].xCoord, keys[i].xCoord);
            assertEq(shards[i].yParity, keys[i].yParity);
        }

        // // Replace one shard key
        signer = new Signer(12345);
        keys[0].xCoord = signer.xCoord();
        keys[0].yParity = signer.yParity();
        _sortTssKeys(keys);
        vm.prank(ADMIN, ADMIN);
        gateway.setShards(keys);

        // Check shards keys
        shards = gateway.shards();
        _sortTssKeys(shards);
        for (uint256 i = 0; i < shards.length; i++) {
            assertEq(shards[i].xCoord, keys[i].xCoord);
            assertEq(shards[i].yParity, keys[i].yParity);
        }
    }

    function test_shardEvents() external {
        TssKey[] memory keys = new TssKey[](10);

        // create random shard keys
        Signer signer;
        for (uint256 i = 0; i < keys.length; i++) {
            signer = new Signer(i + 1);
            keys[i] = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        }
        _sortTssKeys(keys);

        // set shards
        vm.prank(ADMIN, ADMIN);
        vm.expectEmit(false, false, false, true);
        emit IExecutor.ShardsRegistered(keys);
        gateway.setShards(keys);

        // set a shard which is already registered and verify that is does not emit a event.
        vm.prank(ADMIN, ADMIN);
        vm.recordLogs();
        gateway.setShard(keys[0]);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 0);

        // Revoke a registered shard thats not registered.
        uint256 unregisteredSignerKey = 11;
        signer = new Signer(unregisteredSignerKey);
        TssKey memory nonRegisteredKey = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        vm.prank(ADMIN, ADMIN);
        vm.recordLogs();
        gateway.revokeShard(nonRegisteredKey);
        Vm.Log[] memory entries1 = vm.getRecordedLogs();
        assertEq(entries1.length, 0);

        // Revoke a registered shard
        vm.prank(ADMIN, ADMIN);
        TssKey[] memory unregisteredShardKey = new TssKey[](1);
        unregisteredShardKey[0] = keys[0];
        vm.expectEmit(false, false, false, true);
        emit IExecutor.ShardsUnregistered(unregisteredShardKey);
        gateway.revokeShard(keys[0]);

        // Register a revoked shard
        vm.prank(ADMIN, ADMIN);
        vm.expectEmit(false, false, false, true);
        emit IExecutor.ShardsRegistered(unregisteredShardKey);
        gateway.setShard(unregisteredShardKey[0]);

        // Revoke half of the keys and verify event length
        vm.prank(ADMIN, ADMIN);
        uint256 halfKeysLength = keys.length / 2;
        uint256 secondHalfLength = keys.length - halfKeysLength;
        TssKey[] memory firstHalf = new TssKey[](halfKeysLength);
        TssKey[] memory secondHalf = new TssKey[](secondHalfLength);
        for (uint256 i = 0; i < keys.length; i++) {
            if (i < halfKeysLength) {
                firstHalf[i] = keys[i];
            } else {
                secondHalf[i - halfKeysLength] = keys[i];
            }
        }
        vm.expectEmit(false, false, false, true);
        emit IExecutor.ShardsUnregistered(firstHalf);
        gateway.revokeShards(firstHalf);

        // register first half keys and check if the other half is unregistered
        vm.prank(ADMIN, ADMIN);
        vm.expectEmit(false, false, false, true);
        emit IExecutor.ShardsRegistered(firstHalf);
        emit IExecutor.ShardsUnregistered(secondHalf);
        gateway.setShards(firstHalf);
    }

    function test_estimateMessageCost() external {
        vm.txGasPrice(1);
        uint256 cost = gateway.estimateMessageCost(DEST_NETWORK_ID, 96, 100000);
        assertEq(cost, GasUtils.EXECUTION_BASE_COST + 133824 + 66);
    }

    function test_checkPayloadSize() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(bytes20(keccak256("dummy_address"))),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 0,
            nonce: 0,
            data: new bytes(24576 + 1)
        });

        Signature memory sig = sign(gmp);

        // Expect a revert
        vm.expectRevert("msg data too large");
        gateway.execute{gas: 1_000_000}(sig, gmp);
        uint256 ctxExecutionCost = vm.lastCallGas().gasTotalUsed;
        assertLt(ctxExecutionCost, GasUtils.computeExecutionRefund(uint16(gmp.data.length), 0), "revert should use less gas!!");
    }

    /**
     * @dev Test the gas metering for the `execute` function.
     */
    /*function test_gasMeter(uint16 messageSize) external {
        vm.assume(messageSize <= 0x6000 && messageSize >= 32);
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1000,
            nonce: 0,
            data: new bytes(messageSize)
        });
        {
            bytes memory gmpData = gmp.data;
            assembly {
                mstore(add(gmpData, 0x20), 1000)
            }
        }
        Signature memory sig = sign(gmp);

        // Calculate memory expansion cost and base cost
        uint256 executionCost = GasUtils.computeExecutionRefund(uint16(gmp.data.length), gmp.gasLimit);
        uint256 gasNeeded = GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit);

        vm.startPrank(sender);
        vm.expectRevert();
        gateway.execute{gas: gasNeeded - 1}(sig, gmp);

        // Check if the gateway has enough balance to refund the gas
        uint256 gatewayBalance = address(gateway).balance;
        uint256 senderBalance = address(sender).balance;
        assertGe(gatewayBalance, executionCost);
        assertGe(senderBalance, gasNeeded);

        (GmpStatus status, bytes32 returned) = gateway.execute{gas: gasNeeded}(sig, gmp);
        uint256 ctxExecutionCost = vm.lastCallGas().gasTotalUsed;

        assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "gmp execution failed");
        assertEq(uint256(returned), gmp.gasLimit, "wrong gmp return value");
        assertEq(ctxExecutionCost, executionCost, "ctx.executionCost != executionCost");
        assertEq(gatewayBalance - address(gateway).balance, executionCost, "wrong refund amount");
        assertEq(senderBalance, address(sender).balance, "sender balance should not change");

        // Calculate the minimal gmp value minus one
        uint256 value;
        {
            uint256 nonZeros = GasUtils.countNonZeros(gmp.data);
            uint256 zeros = gmp.data.length - nonZeros;
            value = GasUtils.estimateGas(uint16(nonZeros), uint16(zeros), gmp.gasLimit);
        }
        // Add sufficient gas
        gasNeeded += gmp.data.length * 8;

        // Must revert if fund are insufficient
        vm.expectRevert("insufficient tx value");
        gateway.submitMessage{value: value - 1}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);

        {
            bytes memory submitEncoded =
                abi.encodeCall(IGateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
            assertEq(submitEncoded.length, ((gmp.data.length + 31) & 0xffe0) + 164, "wrong encoded length");
        }

        // Must work if the funds are sufficient
        gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
        ctxExecutionCost = vm.lastCallGas().gasTotalUsed;

        assertEq(
            ctxExecutionCost,
            GasUtils.submitMessageGasCost(uint16(gmp.data.length)) - 4500 + GasUtils.FIRST_MESSAGE_EXTRA_COST,
            "unexpected submit message gas cost"
        );
    }*/

    function test_submitMessageMeter() external {
        uint16 messageSize = 32;
        vm.assume(messageSize <= 0x6000);
        vm.txGasPrice(1);
        address sender = address(0xabcdef);
        vm.deal(sender, 10 ether);

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: DEST_NETWORK_ID,
            dest: address(bytes20(keccak256("dummy_address"))),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 0,
            nonce: 0,
            data: new bytes(messageSize)
        });

        // Transaction Parameters
        uint256 gasLimit = GasUtils.submitMessageGasNeeded(uint16(gmp.data.length));

        // Submit the transaction
        uint256 value;
        {
            uint256 nonZeros = GasUtils.countNonZeros(gmp.data);
            uint256 zeros = gmp.data.length - nonZeros;
            value = GasUtils.estimateGas(uint16(nonZeros), uint16(zeros), gmp.gasLimit);
        }

        uint256 snapshot = vm.snapshotState();
        // Must work if the funds and gas limit are sufficient
        bytes32 id = gmp.messageId();
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id,
            GmpSender.unwrap(gmp.source),
            gmp.dest,
            gmp.destNetwork,
            uint64(gmp.gasLimit),
            uint64(value),
            gmp.nonce,
            gmp.data
        );
        console.log("expect: ", value);
        gasLimit += GasUtils.FIRST_MESSAGE_EXTRA_COST;
        vm.startPrank(sender);
        bytes32 rid = gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
        uint256 executionCost = vm.lastCallGas().gasTotalUsed;
        vm.stopPrank();
        assertEq(rid, id, "unexpected GMP id");

        // Verify the execution cost
        assertEq(
            executionCost,
            GasUtils.submitMessageGasCost(uint16(gmp.data.length)) + GasUtils.FIRST_MESSAGE_EXTRA_COST,
            "unexpected submit message gas cost"
        );

        // Must revert if fund are insufficient
        vm.revertToState(snapshot);
        value -= 1;
        vm.expectRevert("insufficient tx value");
        gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
    }

    function test_refund() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);

        // GMP message gas used
        uint64 gmpGasUsed = 2_000;

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gmpGasUsed,
            nonce: 1,
            data: abi.encodePacked(uint256(gmpGasUsed))
        });
        Signature memory sig = sign(gmp);

        // Estimate execution cost
        uint256 executionCost = GasUtils.computeExecutionRefund(uint16(gmp.data.length), gmp.gasLimit);
        uint256 gasNeeded = GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit);

        // Execute GMP message
        uint256 beforeBalance = sender.balance;
        {
            (GmpStatus status, bytes32 returned) = gateway.execute{gas: gasNeeded}(sig, gmp);
            uint256 ctxExecutionCost = vm.lastCallGas().gasTotalUsed;
            assertEq(ctxExecutionCost, executionCost, "unexpected gas used");

            // Verify the GMP message status
            assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "Unexpected GMP status");
            Gateway.GmpInfo memory info = gateway.gmpInfo(gmp.messageId());
            assertEq(
                uint256(info.status), uint256(GmpStatus.SUCCESS), "GMP status stored doesn't match the returned status"
            );
            assertEq(returned, bytes32(uint256(gmp.gasLimit)), "unexpected GMP result");
        }

        // Verify the gas refund
        uint256 afterBalance = sender.balance;
        assertEq(beforeBalance, afterBalance, "wrong refund amount");
    }

    function test_ExecuteRevertsWrongNetwork() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);


        GmpMessage memory wrongNetwork = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(0x0),
            destNetwork: SRC_NETWORK_ID,
            gasLimit: 1000,
            nonce: 1,
            data: ""
        });
        Signature memory wrongNetworkSig = sign(wrongNetwork);
        vm.startPrank(sender);
        vm.expectRevert("invalid gmp network");
        gateway.execute{gas: 1_000_000}(wrongNetworkSig, wrongNetwork);
        vm.stopPrank();
    }

    function test_ExecuteRevertsBelowGasLimit() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100_000,
            nonce: 1,
            data: abi.encode(uint256(100_000))
        });
        Signature memory sig = sign(gmp);

        // Deposit funds
        uint256 executionCost = GasUtils.computeExecutionRefund(uint16(gmp.data.length), gmp.gasLimit);

        // Execute GMP message
        vm.expectRevert("insufficient gas to execute GMP message");
        gateway.execute{gas: executionCost}(sig, gmp);
    }

    function test_executeRevertsAlreadyExecuted() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1000,
            nonce: 1,
            data: abi.encode(uint256(1000))
        });
        Signature memory sig = sign(gmp);

        // Execute GMP message first time
        vm.startPrank(sender);
        (GmpStatus status, bytes32 result) = gateway.execute{gas: 1_000_000}(sig, gmp);
        vm.stopPrank();
        assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "unexpected GMP status");
        assertEq(gmp.gasLimit, uint256(result), "unexpected GMP result");

        // Execute GMP message second time
        vm.expectRevert("message already executed");
        gateway.execute(sig, gmp);
    }

    function test_submitGmpMessage() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: DEST_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100_000,
            nonce: 0,
            data: abi.encodePacked(uint256(100_000))
        });
        bytes32 id = gmp.messageId();

        // Check the previous message hash
        assertEq(gateway.nonceOf(gmp.source.toAddress()), 0, "wrong previous message hash");

        // Compute GMP message price
        uint256 value;
        {
            uint16 nonZeros = uint16(GasUtils.countNonZeros(gmp.data));
            uint16 zeros = uint16(gmp.data.length) - nonZeros;
            value = GasUtils.estimateWeiCost(UFloatMath.ONE, 0, nonZeros, zeros, gmp.gasLimit);
        }

        // Submit message with insufficient funds
        value -= 1;
        vm.expectRevert("insufficient tx value");
        gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);

        // Submit message with sufficient funds
        value += 1;
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id,
            GmpSender.unwrap(gmp.source),
            gmp.dest,
            gmp.destNetwork,
            uint64(gmp.gasLimit),
            uint64(value),
            gmp.nonce,
            gmp.data
        );
        bytes32 rid = gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
        uint256 ctxExecutionCost = vm.lastCallGas().gasTotalUsed;
        assertEq(rid, id, "unexpected GMP id");

        // Verify the gas cost
        uint256 expectedCost = GasUtils.submitMessageGasCost(uint16(gmp.data.length)) - 6500;
        assertEq(ctxExecutionCost, expectedCost + GasUtils.FIRST_MESSAGE_EXTRA_COST, "unexpected execution gas cost in first call");

        // Now the second GMP message nonce must be equals to previous message nonce + 1.
        gmp.nonce = gateway.nonceOf(gmp.source.toAddress());
        id = gmp.messageId();

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id,
            GmpSender.unwrap(gmp.source),
            gmp.dest,
            gmp.destNetwork,
            uint64(gmp.gasLimit),
            uint64(value),
            gmp.nonce,
            gmp.data
        );
        rid = gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
        ctxExecutionCost = vm.lastCallGas().gasTotalUsed;
        assertEq(rid, id, "unexpected GMP id");
        assertEq(ctxExecutionCost, expectedCost - 6800, "unexpected execution gas cost in second call");
    }
}
