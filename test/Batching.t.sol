// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Batch.t.sol)

pragma solidity >=0.8.0;

import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {TestUtils} from "./TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway} from "../src/Gateway.sol";
import {GasUtils} from "../src/GasUtils.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {
    Batch,
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
    using PrimitiveUtils for address;

    uint256 private constant ADMIN_SECRET = 0x955acb49dbb669143455ffbf98e30ae5b2d95343c8b46ce10bf1975d722e8001;
    VmSafe.Wallet internal admin;

    uint256 private constant SHARD_SECRET = 0x42;
    VmSafe.Wallet internal shard;

    Gateway internal gateway;

    // Chronicle TSS Secret
    uint256 private constant SIGNING_NONCE = 0x69;

    // Netowrk ids
    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;

    IGmpReceiver internal receiver1;
    IGmpReceiver internal receiver2;

    constructor() {
        // Create the Admin account
        admin = vm.createWallet(ADMIN_SECRET);
        vm.deal(admin.addr, 100 ether);

        // Create the Shard account
        shard = vm.createWallet(SHARD_SECRET);
        vm.deal(shard.addr, 10 ether);

        gateway = TestUtils.setupGateway(admin, DEST_NETWORK_ID);
        TestUtils.setMockShards(admin, address(gateway), shard);
        TestUtils.setMockRoute(admin, address(gateway), DEST_NETWORK_ID);
        vm.deal(address(gateway), 10 ether);

        receiver1 = IGmpReceiver(new GasSpender());
        receiver2 = IGmpReceiver(new GasSpender());
    }

    function test_execute_batch() external {
        uint64 gasLimit = 7845;
        Batch memory batch = TestUtils.makeBatch(
            0,
            GmpMessage({
                source: admin.addr.toSender(),
                srcNetwork: SRC_NETWORK_ID,
                dest: address(receiver1),
                destNetwork: DEST_NETWORK_ID,
                gasLimit: gasLimit,
                nonce: gateway.nonces(admin.addr),
                data: abi.encode(gasLimit)
            })
        );
        Signature memory sig = TestUtils.sign(shard, gateway, batch, SIGNING_NONCE);
        gateway.execute(sig, batch);
    }

    function test_execute_batch_2() external {
        uint64 gasLimit = 7845;
        GatewayOp[] memory ops = new GatewayOp[](2);
        ops[0] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: admin.addr.toSender(),
                    srcNetwork: SRC_NETWORK_ID,
                    dest: address(receiver1),
                    destNetwork: DEST_NETWORK_ID,
                    gasLimit: gasLimit,
                    nonce: gateway.nonces(admin.addr),
                    data: abi.encode(gasLimit)
                })
            )
        });
        ops[1] = GatewayOp({
            command: Command.GMP,
            params: abi.encode(
                GmpMessage({
                    source: admin.addr.toSender(),
                    srcNetwork: SRC_NETWORK_ID,
                    dest: address(receiver2),
                    destNetwork: DEST_NETWORK_ID,
                    gasLimit: gasLimit,
                    nonce: gateway.nonces(admin.addr) + 1,
                    data: abi.encode(gasLimit)
                })
            )
        });
        Batch memory batch = Batch({version: 0, batchId: uint64(uint256(keccak256("some batch"))), ops: ops});

        Signature memory sig = TestUtils.sign(shard, gateway, batch, SIGNING_NONCE);
        gateway.execute(sig, batch);
    }
}
