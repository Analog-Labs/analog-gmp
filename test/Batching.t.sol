// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Batch.t.sol)

pragma solidity >=0.8.0;

import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {TestUtils} from "./TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {GasUtils} from "../src/GasUtils.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {
    InboundMessage,
    GatewayOp,
    Command,
    GmpMessage,
    GmpCallback,
    Signature,
    TssKey,
    GmpStatus,
    PrimitiveUtils,
    GMP_VERSION
} from "../src/Primitives.sol";

contract Batching is Test {
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpCallback;
    using PrimitiveUtils for address;
    using BranchlessMath for uint256;

    uint256 private constant ADMIN_SECRET = 0x955acb49dbb669143455ffbf98e30ae5b2d95343c8b46ce10bf1975d722e8001;
    VmSafe.Wallet internal ADMIN;

    uint256 private constant SHARD_SECRET = 0x42;
    VmSafe.Wallet internal SHARD;

    address internal GATEWAY_PROXY;

    // Chronicle TSS Secret
    uint256 private constant SIGNING_NONCE = 0x69;

    // Netowrk ids
    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;

    IGmpReceiver internal receiver1;
    IGmpReceiver internal receiver2;

    constructor() {
        // Create the Admin account
        ADMIN = vm.createWallet(ADMIN_SECRET);
        vm.deal(ADMIN.addr, 100 ether);

        // Create the Shard account
        SHARD = vm.createWallet(SHARD_SECRET);
        vm.deal(SHARD.addr, 10 ether);

        IGateway gw = TestUtils.setupGateway(ADMIN, DEST_NETWORK_ID);
        GATEWAY_PROXY = address(gw);
        TestUtils.setMockShard(ADMIN, address(gw), SHARD);
        TestUtils.setMockRoute(ADMIN, address(gw), SRC_NETWORK_ID);
        TestUtils.setMockRoute(ADMIN, address(gw), DEST_NETWORK_ID);
        vm.deal(address(gw), 10 ether);

        receiver1 = IGmpReceiver(new GasSpender());
        receiver2 = IGmpReceiver(new GasSpender());
    }

    function test_buildBatch() external {
        GatewayOp[] memory ops = new GatewayOp[](2);
        ops[0] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: 0x7777777777777777777777777777777777777777777777777777777777777777,
                    srcNetwork: 0x8888,
                    dest: 0x9999999999999999999999999999999999999999,
                    destNetwork: 0xAAAA,
                    gasLimit: 0xBBBBBBBBBBBBBBBB,
                    nonce: 0xCCCCCCCCCCCCCCCC,
                    data: abi.encode(uint256(0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD))
                })
            )
        });
        // data: hex"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

        ops[1] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: 0x7070707070707070707070707070707070707070707070707070707070707070,
                    srcNetwork: 0x8080,
                    dest: 0x9090909090909090909090909090909090909090,
                    destNetwork: 0xA0A0,
                    gasLimit: 0xB0B0B0B0B0B0B0B0,
                    nonce: 0xC0C0C0C0C0C0C0C0,
                    data: abi.encode(uint256(0xD0D0D0D0D0D0D0D0D0D0D0D0D0D0D0))
                })
            )
        });
        // data: hex"D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0"

        InboundMessage memory inbound = InboundMessage({version: 0x44, batchID: 0x5555555555555555, ops: ops});
        Signature memory sig = Signature({
            xCoord: 0x1111111111111111111111111111111111111111111111111111111111111111,
            e: 0x2222222222222222222222222222222222222222222222222222222222222222,
            s: 0x3333333333333333333333333333333333333333333333333333333333333333
        });
        Gateway(GATEWAY_PROXY).batchExecute(sig, inbound);
    }

    function test_buildBatch2() external {
        uint64 gasLimit = 7845;
        GatewayOp[] memory ops = new GatewayOp[](1);
        ops[0] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: ADMIN.addr.toSender(),
                    srcNetwork: SRC_NETWORK_ID,
                    dest: address(receiver1),
                    destNetwork: DEST_NETWORK_ID,
                    gasLimit: gasLimit,
                    nonce: 0,
                    data: abi.encode(gasLimit)
                })
            )
        });
        InboundMessage memory inbound =
            InboundMessage({version: 1, batchID: uint64(uint256(keccak256("some batch"))), ops: ops});

        Signature memory sig = TestUtils.sign(SHARD, Gateway(GATEWAY_PROXY), inbound, SIGNING_NONCE);
        Gateway(GATEWAY_PROXY).batchExecute(sig, inbound);
    }

    function test_batch_debug() external {
        vm.txGasPrice(1);
        uint64 gasLimit = 7845;

        /////////////////////
        // Build the batch //
        /////////////////////
        GatewayOp[] memory ops = new GatewayOp[](2);
        ops[0] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: ADMIN.addr.toSender(),
                    srcNetwork: SRC_NETWORK_ID,
                    dest: address(receiver1),
                    destNetwork: DEST_NETWORK_ID,
                    gasLimit: gasLimit,
                    nonce: 0,
                    data: abi.encode(gasLimit)
                })
            )
        });
        ops[1] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: ADMIN.addr.toSender(),
                    srcNetwork: SRC_NETWORK_ID,
                    dest: address(receiver2),
                    destNetwork: DEST_NETWORK_ID,
                    gasLimit: gasLimit,
                    nonce: 0,
                    data: abi.encode(gasLimit)
                })
            )
        });
        InboundMessage memory inbound =
            InboundMessage({version: 1, batchID: uint64(uint256(keccak256("some batch"))), ops: ops});

        Signature memory sig = TestUtils.sign(SHARD, Gateway(GATEWAY_PROXY), inbound, SIGNING_NONCE);
        Gateway(GATEWAY_PROXY).batchExecute(sig, inbound);
    }
}
