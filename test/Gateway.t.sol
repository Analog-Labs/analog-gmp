// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Gateway.t.sol)

pragma solidity >=0.8.0;

import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "./TestUtils.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway} from "../src/Gateway.sol";
import {GasUtils} from "../src/GasUtils.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {
    Batch,
    GmpMessage,
    Signature,
    TssKey,
    GmpCallback,
    GmpStatus,
    PrimitiveUtils,
    GMP_VERSION
} from "../src/Primitives.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract TestGatewayV2 is Gateway {
    string public constant VERSION = "v2.0";
    uint256 public newFeature;

    function setNewFeature(uint256 _val) external onlyOwner {
        newFeature = _val;
    }

    function getNewFeature() external view onlyOwner returns (uint256) {
        return newFeature;
    }
}

contract GatewayTest is Test {
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for address;
    using PrimitiveUtils for bytes32;
    using BranchlessMath for uint256;

    Gateway internal gateway;
    VmSafe.Wallet internal admin;

    // Chronicle TSS Secret
    uint256 private constant SECRET = 0x42;
    uint256 private constant SIGNING_NONCE = 0x69;

    // Receiver Contract, the will waste the exact amount of gas you sent to it in the data field
    IGmpReceiver internal receiver;

    // Netowrk ids
    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;

    constructor() {
        admin = vm.createWallet(SECRET);
        gateway = Gateway(payable(address(TestUtils.setupGateway(admin, DEST_NETWORK_ID))));
        TestUtils.setMockShards(admin, address(gateway), admin);
        TestUtils.setMockRoute(admin, address(gateway), DEST_NETWORK_ID);
        receiver = IGmpReceiver(new GasSpender());
    }

    function setUp() external view {
        // check block gas limit as gas left
        assertEq(block.gaslimit, 30_000_000);
        assertTrue(gasleft() >= 10_000_000);
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

    function testMessageId() public pure {
        GmpMessage memory gmp = GmpMessage({
            source: address(0x1).toSender(),
            srcNetwork: 42,
            dest: address(0x1),
            destNetwork: 69,
            gasLimit: 0,
            nonce: 2,
            data: "42"
        });
        bytes32 msgId = keccak256(
            abi.encode(GMP_VERSION, gmp.source, gmp.srcNetwork, gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.nonce)
        );
        assertEq(gmp.messageId(), msgId);
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
        address notAdmin = address(0x0000000000000000000000000000000000000000);
        vm.prank(notAdmin);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notAdmin));
        gateway.setShards(keys);

        // Set shards keys must work
        vm.prank(admin.addr, admin.addr);
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
        vm.prank(admin.addr, admin.addr);
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
        TssKey[] memory keys = new TssKey[](2);

        // create random shard keys
        Signer signer;
        for (uint256 i = 0; i < keys.length; i++) {
            signer = new Signer(i + 1);
            keys[i] = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        }
        _sortTssKeys(keys);

        // set shards
        vm.prank(admin.addr, admin.addr);
        vm.expectEmit(false, false, false, true);
        emit Gateway.ShardsRegistered(keys);
        gateway.setShards(keys);

        // set a shard which is already registered and verify that is does not emit a event.
        vm.prank(admin.addr, admin.addr);
        vm.recordLogs();
        gateway.setShards(keys);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 0);

        // Revoke half of the keys and verify event length
        vm.prank(admin.addr, admin.addr);
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
        vm.recordLogs();
        vm.expectEmit(false, false, false, true);
        emit Gateway.ShardsUnregistered(firstHalf);
        gateway.setShards(secondHalf);

        // register first half keys and check if the other half is unregistered
        vm.prank(admin.addr, admin.addr);
        vm.expectEmit(false, false, false, true);
        emit Gateway.ShardsRegistered(firstHalf);
        emit Gateway.ShardsUnregistered(secondHalf);
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
            source: sender.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(bytes20(keccak256("dummy_address"))),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 0,
            nonce: 0,
            data: new bytes(24576 + 1)
        });
        Batch memory batch = TestUtils.makeBatch(0, gmp);
        Signature memory sig = TestUtils.sign(admin, gateway, batch, SIGNING_NONCE);

        // Expect a revert
        vm.expectRevert("msg data too large");
        gateway.execute{gas: 1_000_000}(sig, batch);
        uint256 ctxExecutionCost = vm.lastCallGas().gasTotalUsed;
        assertLt(
            ctxExecutionCost, GasUtils.executionGasUsed(uint16(gmp.data.length), 0), "revert should use less gas!!"
        );
    }

    function test_refund() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);

        // GMP message gas used
        uint64 gmpGasUsed = 2_000;

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gmpGasUsed,
            nonce: 0,
            data: abi.encodePacked(uint256(gmpGasUsed))
        });
        Batch memory batch = TestUtils.makeBatch(0, gmp);
        Signature memory sig = TestUtils.sign(admin, gateway, batch, SIGNING_NONCE);

        // Estimate execution cost

        // Execute GMP message
        uint256 beforeBalance = sender.balance;
        {
            gateway.execute(sig, batch);
            uint256 cGasUsed = GasUtils.executionGasUsed(uint16(gmp.data.length), gmp.gasLimit);
            uint256 mGasUsed = vm.lastCallGas().gasTotalUsed;
            assertEq(cGasUsed, mGasUsed, "unexpected gas used");
            GmpStatus status = gateway.messages(gmp.messageId());
            assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "Unexpected GMP status");
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
            source: sender.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(0x0),
            destNetwork: SRC_NETWORK_ID,
            gasLimit: 1000,
            nonce: 1,
            data: ""
        });
        Batch memory batch = TestUtils.makeBatch(0, wrongNetwork);
        Signature memory wrongNetworkSig = TestUtils.sign(admin, gateway, batch, SIGNING_NONCE);
        vm.startPrank(sender);
        vm.expectRevert("invalid gmp network");
        gateway.execute{gas: 1_000_000}(wrongNetworkSig, batch);
        vm.stopPrank();
    }

    function test_ExecuteRevertsBelowGasLimit() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100_000,
            nonce: 1,
            data: abi.encode(uint256(100_000))
        });
        Batch memory batch = TestUtils.makeBatch(0, gmp);
        Signature memory sig = TestUtils.sign(admin, gateway, batch, SIGNING_NONCE);

        // Deposit funds
        uint256 cGasUsed = GasUtils.executionGasUsed(uint16(gmp.data.length), 0);

        // Execute GMP message
        vm.expectRevert("insufficient gas to execute GMP message");
        gateway.execute{gas: cGasUsed}(sig, batch);
    }

    function test_executeRevertsAlreadyExecuted() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1000,
            nonce: 1,
            data: abi.encode(uint256(1000))
        });
        Batch memory batch = TestUtils.makeBatch(0, gmp);
        Signature memory sig = TestUtils.sign(admin, gateway, batch, SIGNING_NONCE);

        // Execute GMP message first time
        vm.startPrank(sender);
        gateway.execute{gas: 1_000_000}(sig, batch);
        vm.stopPrank();
        GmpStatus status = gateway.messages(gmp.messageId());
        assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "unexpected GMP status");

        // Execute GMP message second time
        vm.expectRevert("message already executed");
        gateway.execute(sig, batch);
    }

    function test_submitGmpMessage() external {
        vm.txGasPrice(1);
        address sender = address(0xdead_beef99);
        vm.deal(sender, 10 ether);
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(),
            srcNetwork: DEST_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100_000,
            nonce: 0,
            data: abi.encodePacked(uint256(100_000))
        });
        bytes32 id = gmp.messageId();

        // Check the previous message hash
        assertEq(gateway.nonces(gmp.source.toAddress()), 0, "wrong previous message hash");

        // Compute GMP message price
        uint256 value;
        {
            uint16 nonZeros = uint16(TestUtils.countNonZeros(gmp.data));
            uint16 zeros = uint16(gmp.data.length) - nonZeros;
            value = GasUtils.estimateGas(nonZeros, zeros, gmp.gasLimit);
        }

        // Submit message with insufficient funds
        vm.expectRevert("insufficient tx value");
        gateway.submitMessage{value: value - 1}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);

        // Submit message with sufficient funds
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, gmp.source, gmp.dest, gmp.destNetwork, uint64(gmp.gasLimit), uint64(value), gmp.nonce, gmp.data
        );
        vm.startPrank(sender);
        bytes32 rid = gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
        vm.stopPrank();
        assertEq(rid, id, "unexpected GMP id");

        // Now the second GMP message nonce must be equals to previous message nonce + 1.
        gmp.nonce = gateway.nonces(gmp.source.toAddress());
        id = gmp.messageId();

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, gmp.source, gmp.dest, gmp.destNetwork, uint64(gmp.gasLimit), uint64(value), gmp.nonce, gmp.data
        );
        vm.startPrank(sender);
        rid = gateway.submitMessage{value: value}(gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data);
        vm.stopPrank();
        assertEq(rid, id, "unexpected GMP id");
    }

    function test_upgradeOnlyAdmin() public {
        TestGatewayV2 gatewayv2 = new TestGatewayV2();
        address notAdmin = address(0x0000000000000000000000000000000000000000);
        vm.startPrank(notAdmin);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notAdmin));
        gateway.upgradeToAndCall(address(gatewayv2), "");
        vm.stopPrank();
        vm.startPrank(admin.addr);
        gateway.upgradeToAndCall(address(gatewayv2), "");
    }

    function test_storagePreservationAfterUpgrade() public {
        uint256 initialNetworkId = gateway.networkId();

        TestGatewayV2 gatewayV2 = new TestGatewayV2();
        vm.prank(admin.addr);
        gateway.upgradeToAndCall(address(gatewayV2), "");
        assertEq(gateway.networkId(), initialNetworkId, "Network ID changed");
    }

    function test_newFeatureAfterUpgrade() public {
        TestGatewayV2 gatewayV2 = new TestGatewayV2();
        vm.prank(admin.addr);
        gateway.upgradeToAndCall(address(gatewayV2), "");

        TestGatewayV2 upgraded = TestGatewayV2(address(gateway));

        address notAdmin = address(0x0000000000000000000000000000000000000000);
        vm.prank(notAdmin);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notAdmin));
        upgraded.setNewFeature(100);

        vm.prank(admin.addr);
        uint256 newFeature = 100;
        upgraded.setNewFeature(newFeature);
        vm.prank(admin.addr);
        uint256 receivedFeature = upgraded.getNewFeature();
        assertEq(newFeature, receivedFeature);
    }
}
