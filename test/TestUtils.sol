// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/TestUtils.sol)

pragma solidity >=0.8.0;

import {VmSafe, Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {Gateway} from "../src/Gateway.sol";
import {Hashing} from "../src/utils/Hashing.sol";
import {GmpMessage, Signature, TssKey, Route, PrimitiveUtils, Batch, GatewayOp, Command} from "../src/Primitives.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract SigningHash {
    using PrimitiveUtils for GmpMessage;

    Gateway immutable gw;

    constructor(address gateway) {
        gw = Gateway(payable(gateway));
    }

    function signingHash(Batch calldata batch) external view returns (bytes32) {
        bytes32 rootHash = bytes32(0);

        GatewayOp[] calldata ops = batch.ops;
        for (uint256 i = 0; i < ops.length; i++) {
            GatewayOp calldata op = ops[i];
            bytes calldata params = op.params;

            bytes32 operationHash;
            if (op.command == Command.GMP) {
                GmpMessage calldata gmp;
                assembly {
                    gmp := add(params.offset, 0x20)
                }
                operationHash = gmp.opHash();
            } else {
                TssKey calldata tssKey;
                assembly {
                    tssKey := params.offset
                }
                operationHash = Hashing.hash(tssKey.yParity, tssKey.xCoord);
            }
            rootHash = Hashing.hash(uint256(rootHash), uint256(op.command), uint256(operationHash));
        }
        rootHash = Hashing.hash(batch.version, batch.batchId, uint256(rootHash));
        return keccak256(
            abi.encodePacked("Analog GMP v2", gw.networkId(), bytes32(uint256(uint160(address(gw)))), rootHash)
        );
    }
}

/**
 * @dev Utilities for testing purposes
 */
library TestUtils {
    using PrimitiveUtils for GmpMessage;

    // Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
    address internal constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm internal constant vm = Vm(VM_ADDRESS);

    function setupGateway(VmSafe.Wallet memory admin, uint16 network) internal returns (Gateway gw) {
        vm.startPrank(admin.addr, admin.addr);

        Gateway gateway = new Gateway();
        bytes memory initData = abi.encodeWithSelector(Gateway.initialize.selector, network);
        ERC1967Proxy proxy = new ERC1967Proxy(address(gateway), initData);
        console.log("Implementation:", address(gateway));
        console.log("Proxy:", address(proxy));

        vm.deal(address(proxy), 10 ether);
        vm.stopPrank();
        return Gateway(payable(address(proxy)));
    }

    function setMockShards(VmSafe.Wallet memory admin, address gateway, VmSafe.Wallet memory shard) internal {
        Signer signer = new Signer(shard.privateKey);
        TssKey[] memory keys = new TssKey[](1);
        keys[0] = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        Gateway gw = Gateway(payable(gateway));
        vm.startPrank(admin.addr, admin.addr);
        gw.setShards(keys);
        vm.stopPrank();
    }

    function setMockRoute(VmSafe.Wallet memory admin, address gateway, uint16 network) internal {
        Gateway gw = Gateway(payable(gateway));
        vm.startPrank(admin.addr, admin.addr);
        gw.setRoute(
            Route({
                networkId: network,
                gasLimit: 1_000_000,
                baseFee: 0,
                gateway: bytes32(uint256(1)),
                relativeGasPriceNumerator: 1,
                relativeGasPriceDenominator: 1
            })
        );
        vm.stopPrank();
    }

    function makeBatch(uint64 batch, GmpMessage memory gmp) internal pure returns (Batch memory) {
        GatewayOp[] memory ops = new GatewayOp[](1);
        ops[0] = GatewayOp({command: Command.GMP, params: abi.encode(gmp)});
        return Batch({version: 0, batchId: batch, ops: ops});
    }

    function sign(VmSafe.Wallet memory shard, bytes32 hash, uint256 nonce) internal returns (Signature memory sig) {
        console.log("signing");
        console.logBytes32(hash);
        Signer signer = new Signer(shard.privateKey);
        (uint256 e, uint256 s) = signer.signPrehashed(uint256(hash), nonce);
        return Signature({xCoord: signer.xCoord(), e: e, s: s});
    }

    function sign(VmSafe.Wallet memory shard, GmpMessage memory gmp, uint256 nonce)
        internal
        returns (Signature memory sig)
    {
        bytes32 hash = gmp.opHash();
        return TestUtils.sign(shard, hash, nonce);
    }

    function sign(VmSafe.Wallet memory shard, Gateway gw, Batch memory batch, uint256 nonce)
        internal
        returns (Signature memory sig)
    {
        SigningHash hasher = new SigningHash(address(gw));
        bytes32 hash = hasher.signingHash(batch);
        return TestUtils.sign(shard, hash, nonce);
    }
}
