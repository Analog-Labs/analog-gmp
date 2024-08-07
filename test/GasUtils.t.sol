// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/GasUtils.t.sol)

pragma solidity >=0.8.0;

import {Signer} from "frost-evm/sol/Signer.sol";
import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "./TestUtils.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {GasUtils} from "../src/utils/GasUtils.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {UFloat9x56, UFloatMath} from "../src/utils/Float9x56.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {IExecutor} from "../src/interfaces/IExecutor.sol";
import {CallOptions, GatewayUtils} from "./Gateway.t.sol";
import {
    GmpMessage,
    UpdateKeysMessage,
    Signature,
    TssKey,
    Network,
    GmpStatus,
    PrimitiveUtils,
    GmpSender
} from "../src/Primitives.sol";

uint256 constant secret = 0x42;
uint256 constant nonce = 0x69;

contract GasUtilsBase is Test {
    using PrimitiveUtils for UpdateKeysMessage;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpSender;
    using PrimitiveUtils for address;
    using GatewayUtils for CallOptions;
    using BranchlessMath for uint256;

    Gateway internal gateway;
    Signer internal signer;

    // Receiver Contract, the will waste the exact amount of gas you sent to it in the data field
    IGmpReceiver internal receiver;

    // Domain Separators
    bytes32 private _srcDomainSeparator;
    bytes32 private _dstDomainSeparator;

    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;

    constructor() {
        signer = new Signer(secret);
        address deployer = TestUtils.createTestAccount(100 ether);
        vm.startPrank(deployer, deployer);

        // 1 - Deploy the implementation contract
        address proxyAddr = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);
        Gateway implementation = new Gateway(DEST_NETWORK_ID, proxyAddr);

        // 2 - Deploy the Proxy Contract
        TssKey[] memory keys = new TssKey[](1);
        keys[0] = TssKey({yParity: signer.yParity() == 28 ? 1 : 0, xCoord: signer.xCoord()}); // Shard key
        Network[] memory networks = new Network[](2);
        networks[0].id = SRC_NETWORK_ID; // sepolia network id
        networks[0].gateway = proxyAddr; // sepolia proxy address
        networks[1].id = DEST_NETWORK_ID; // shibuya network id
        networks[1].gateway = proxyAddr; // shibuya proxy address
        bytes memory initializer = abi.encodeCall(Gateway.initialize, (msg.sender, keys, networks));
        gateway = Gateway(address(new GatewayProxy(address(implementation), initializer)));
        vm.deal(address(gateway), 100 ether);

        _srcDomainSeparator = GatewayUtils.computeDomainSeparator(SRC_NETWORK_ID, address(gateway));
        _dstDomainSeparator = GatewayUtils.computeDomainSeparator(DEST_NETWORK_ID, address(gateway));

        vm.stopPrank();
    }

    function sign(GmpMessage memory gmp) internal view returns (Signature memory) {
        bytes32 domainSeparator;
        if (gmp.destNetwork == SRC_NETWORK_ID) {
            domainSeparator = _srcDomainSeparator;
        } else {
            domainSeparator = _dstDomainSeparator;
        }
        uint256 hash = uint256(gmp.eip712TypedHash(domainSeparator));
        (uint256 e, uint256 s) = signer.signPrehashed(hash, nonce);
        return Signature({xCoord: signer.xCoord(), e: e, s: s});
    }

    /**
     * @dev Compare the estimated gas cost VS the actual gas cost of the `execute` method.
     */
    function test_baseExecutionCost(uint16 messageSize) external {
        vm.assume(messageSize <= 0x6000);
        vm.txGasPrice(1);
        address sender = TestUtils.createTestAccount(100 ether);

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(bytes20(keccak256("dummy_address"))),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 0,
            salt: 0,
            data: new bytes(messageSize)
        });

        Signature memory sig = sign(gmp);

        // Calculate memory expansion cost and base cost
        (uint256 baseCost,) = GatewayUtils.computeGmpGasCost(sig, gmp);

        // Transaction Parameters
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            // gasLimit: GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit) + baseCost,
            gasLimit: baseCost + 1_000_000,
            executionCost: 0,
            baseCost: 0
        });

        // Execute the GMP message
        ctx.execute(sig, gmp);

        // Calculate the expected base cost
        uint256 dynamicCost =
            GasUtils.computeExecutionRefund(uint16(gmp.data.length), gmp.gasLimit) - GasUtils.EXECUTION_BASE_COST;
        uint256 expectedBaseCost = ctx.executionCost - dynamicCost;
        assertEq(expectedBaseCost, GasUtils.EXECUTION_BASE_COST, "Wrong EXECUTION_BASE_COST");
    }

    function test_gasUtils() external pure {
        assertEq(GasUtils.estimateGas(0, 0, 0), 76208);
        assertEq(GasUtils.estimateGas(0, 33, 0), 76369);
        assertEq(GasUtils.estimateGas(33, 0, 0), 77029);
        assertEq(GasUtils.estimateGas(20, 13, 0), 76769);

        UFloat9x56 one = UFloatMath.ONE;
        assertEq(GasUtils.estimateWeiCost(one, 0, 0, 0, 0), 76208);
        assertEq(GasUtils.estimateWeiCost(one, 0, 0, 33, 0), 76369);
        assertEq(GasUtils.estimateWeiCost(one, 0, 33, 0, 0), 77029);
        assertEq(GasUtils.estimateWeiCost(one, 0, 20, 13, 0), 76769);

        UFloat9x56 two = UFloat9x56.wrap(0x8080000000000000);
        assertEq(GasUtils.estimateWeiCost(two, 0, 0, 0, 0), 76208 * 2);
        assertEq(GasUtils.estimateWeiCost(two, 0, 0, 33, 0), 76369 * 2);
        assertEq(GasUtils.estimateWeiCost(two, 0, 33, 0, 0), 77029 * 2);
        assertEq(GasUtils.estimateWeiCost(two, 0, 20, 13, 0), 76769 * 2);
    }
}

contract GasUtilsTest is GasUtilsBase {
    bytes32 private constant INLINE_BYTECODE = 0x6000823f505a96949290959391f15a607b019091036800000000000000000052;

    constructor() payable {
        bytes memory runtimeCode = type(GasUtilsBase).runtimeCode;
        assembly {
            let size := mload(runtimeCode)
            let i := add(runtimeCode, 32)
            for {
                let chunk := 1
                let end := add(i, size)
            } gt(chunk, 0) { i := add(i, chunk) } {
                chunk := xor(mload(i), 0x8181818181818181818181818181818181818181818181818181818181818181)
                chunk := and(add(chunk, 1), not(chunk))
                chunk := div(chunk, mod(chunk, 0xff))
                chunk := shr(248, mul(0x201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201, chunk))
                chunk := mul(chunk, lt(i, end))
            }
            if not(xor(mload(i), 0x8181818181818181818181818181818181818181818181818181818181818181)) {
                let ptr := mload(0x40)
                mstore(ptr, shl(224, 0x08c379a0))
                mstore(add(ptr, 4), 32) // message offset
                mstore(add(ptr, 36), 29) // message size
                mstore(add(ptr, 68), "Failed to inject the bytecode")
                revert(ptr, 100)
            }
            mstore(add(i, 1), 0x5B)
            mstore(i, INLINE_BYTECODE)
            return(add(runtimeCode, 32), mload(runtimeCode))
        }
    }
}
