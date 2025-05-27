// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Batch.t.sol)

pragma solidity >=0.8.0;

import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {TestUtils} from "./TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {Hashing} from "../src/utils/Hashing.sol";
import {GasUtils} from "../src/utils/GasUtils.sol";
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

    function setUp() external {
        uint256 gasToWaste = 1000;
        vm.startPrank(ADMIN.addr);
        receiver1.onGmpReceived{gas: gasToWaste}(0x0, 1, 0x0, 0, abi.encode(gasToWaste));
        vm.stopPrank();
    }

    function sign(Signer signer, GmpMessage memory gmp) private view returns (Signature memory) {
        GmpCallback memory callback = gmp.memToCallback();
        (uint256 e, uint256 s) = signer.signPrehashed(uint256(callback.opHash), SIGNING_NONCE);
        return Signature({xCoord: signer.xCoord(), e: e, s: s});
    }

    function computeGmpMessageID(GmpMessage calldata message) external pure returns (bytes32) {
        console.logBytes(msg.data);
        return message.intoCallback().messageId();
    }

    function sign(Signer signer, InboundMessage memory message) private view returns (Signature memory sig) {
        signAt(signer, message, sig);
    }

    function computeInboundMessageSigningHash(InboundMessage calldata message) external view returns (bytes32) {
        bytes32 rootHash = bytes32(0);

        GatewayOp[] calldata ops = message.ops;
        for (uint256 i = 0; i < ops.length; i++) {
            GatewayOp calldata op = ops[i];
            bytes calldata params = op.params;

            bytes32 operationHash;
            if (op.command == Command.GMP) {
                GmpMessage calldata gmp;
                assembly {
                    gmp := add(params.offset, 0x20)
                }
                operationHash = gmp.intoCallback().opHash;
            } else {
                TssKey calldata tssKey;
                assembly {
                    tssKey := params.offset
                }
                operationHash = Hashing.hash(tssKey.yParity, tssKey.xCoord);
            }
            rootHash = Hashing.hash(uint256(rootHash), uint256(op.command), uint256(operationHash));
        }
        rootHash = Hashing.hash(message.version, message.batchID, uint256(rootHash));
        return keccak256(
            abi.encodePacked(
                "Analog GMP v2", DEST_NETWORK_ID, bytes32(uint256(uint160(address(GATEWAY_PROXY)))), rootHash
            )
        );
    }

    function signAt(Signer signer, InboundMessage memory message, Signature memory sig) private view {
        bytes32 signingHash = this.computeInboundMessageSigningHash(message);
        (uint256 e, uint256 s) = signer.signPrehashed(uint256(signingHash), SIGNING_NONCE);
        sig.xCoord = signer.xCoord();
        sig.e = e;
        sig.s = s;
    }

    function test_gmp_debug() external {
        vm.txGasPrice(1);
        Signer signer = new Signer(SHARD_SECRET);

        // Build and sign GMP message
        // bytes memory data = new bytes(3070 + 32);
        GmpMessage memory gmp = GmpMessage({
            source: ADMIN.addr.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver1),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 7845,
            nonce: 0,
            data: new bytes(800)
        });
        {
            bytes memory data = gmp.data;
            assembly {
                mstore(add(data, 0x20), 7845)
            }
        }

        Signature memory sig = sign(signer, gmp);

        vm.deal(ADMIN.addr, 100 ether);
        vm.startPrank(ADMIN.addr, ADMIN.addr);
        require(GATEWAY_PROXY.code.length > 0, "gateway proxy not found");
        Gateway(payable(GATEWAY_PROXY)).execute(sig, gmp);
    }

    function batchExecute(Signature calldata, InboundMessage calldata message) external pure {
        console.log("batchExecute:");
        console.logBytes(msg.data);
        for (uint256 i = 0; i < message.ops.length; i++) {
            console.log("\nop:", i);
            GatewayOp calldata op = message.ops[i];
            bytes calldata data = op.params;
            console.logBytes(data);

            uint256 offset;
            GmpMessage calldata gmp;
            assembly {
                offset := data.offset
                gmp := add(offset, 0x20)
            }
            data = gmp.data;

            bytes32 value;
            assembly {
                offset := data.offset
                value := calldataload(value)
            }

            console.log(offset, vm.toString(value));
            console.logBytes(data);
        }
    }

    function test_buildBatch() external view {
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

        bytes memory b = abi.encodeCall(
            Gateway.batchExecute,
            (
                Signature({
                    xCoord: 0x1111111111111111111111111111111111111111111111111111111111111111,
                    e: 0x2222222222222222222222222222222222222222222222222222222222222222,
                    s: 0x3333333333333333333333333333333333333333333333333333333333333333
                }),
                InboundMessage({version: 0x44, batchID: 0x5555555555555555, ops: ops})
            )
        );
        console.logBytes(b);
        (bool success,) = address(this).staticcall(b);
        require(success, "call failed");
        // assertEq(b.length, 1234);
    }

    function test_buildBatch2() external {
        Signer signer = new Signer(SHARD_SECRET);

        // Build and sign GMP
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
        Signature memory sig = Signature({xCoord: 0, e: 0, s: 0});
        InboundMessage memory inbound =
            InboundMessage({version: 1, batchID: uint64(uint256(keccak256("some batch"))), ops: ops});

        // console.log("will sign...");
        signAt(signer, inbound, sig);
        bytes memory b = abi.encodeCall(Gateway.batchExecute, (sig, inbound));
        console.logBytes(b);
        (bool success,) = address(this).staticcall(b);
        require(success, "call failed");
        // assertEq(b.length, 1234);
    }

    function test_batch_debug() external {
        vm.txGasPrice(1);
        Signer signer = new Signer(SHARD_SECRET);
        vm.deal(address(signer), 100 ether);
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

        ////////////////////
        // Sign the batch //
        ////////////////////
        Signature memory sig = sign(signer, inbound);

        // vm.deal(DEPLOYER, 100 ether);
        // vm.startPrank(DEPLOYER, DEPLOYER);
        require(GATEWAY_PROXY.code.length > 0, "gateway proxy not found");

        console.log("will execute..");
        vm.startPrank(address(signer));
        Gateway(GATEWAY_PROXY).batchExecute(sig, inbound);
        //uint256 mGasUsed = vm.lastCallGas().gasTotalUsed;
        //uint256 cGasUsed = GasUtils.executionGasUsed(32, gasLimit);
        //assertEq(cGasUsed, mGasUsed, "unexpected gas used");
        vm.stopPrank();
    }
}
