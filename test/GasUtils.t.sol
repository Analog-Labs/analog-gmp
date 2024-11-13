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

contract GasUtilsMock {
    function execute(Signature calldata, GmpMessage calldata)
        external
        pure
        returns (uint256 baseCost, uint256 nonZeros, uint256 zeros)
    {
        baseCost = GasUtils.txBaseCost();
        nonZeros = GasUtils.countNonZerosCalldata(msg.data);
        zeros = msg.data.length - nonZeros;
    }
}

contract GasUtilsBase is Test {
    using PrimitiveUtils for UpdateKeysMessage;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpSender;
    using PrimitiveUtils for address;
    using GatewayUtils for CallOptions;
    using BranchlessMath for uint256;

    GasUtilsMock internal mock;
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

        // Deploy the GasUtilsMock contract
        mock = new GasUtilsMock();

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

        // Obs: This is a special contract that wastes an exact amount of gas you send to it, helpful for testing GMP refunds and gas limits.
        // See the file `HelperContract.opcode` for more details.
        {
            bytes memory bytecode =
                hex"603c80600a5f395ff3fe5a600201803d523d60209160643560240135146018575bfd5b60365a116018575a604903565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5bf3";
            receiver = IGmpReceiver(TestUtils.deployContract(bytecode));
        }

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
     * @dev Create a GMP message with the provided parameters.
     */
    function _buildGmpMessage(address sender, uint256 gasLimit, uint256 gasUsed, uint256 messageSize)
        private
        view
        returns (GmpMessage memory message, Signature memory signature, CallOptions memory context)
    {
        require(gasUsed == 0 || messageSize >= 32, "If gasUsed > 0, then messageSize must be >= 32");
        require(messageSize <= 0x6000, "message is too big");

        // Setup data and receiver addresses.
        bytes memory data = new bytes(messageSize);
        address gmpReceiver;
        if (gasUsed > 0) {
            gmpReceiver = address(receiver);
            assembly {
                mstore(add(data, 32), gasUsed)
            }
        } else {
            // Create a new unique receiver address for each message, otherwise the gas refund will not work.
            gmpReceiver = address(bytes20(keccak256(abi.encode(sender, gasLimit, messageSize))));
        }

        // Build the GMP message
        message = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: gmpReceiver,
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gasLimit,
            salt: 0,
            data: data
        });

        // Sign the message
        signature = sign(message);

        // Calculate memory expansion cost and base cost
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(signature, message);

        // Set Transaction Parameters
        context = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: GasUtils.executionGasNeeded(message.data.length, message.gasLimit).saturatingAdd(baseCost),
            executionCost: executionCost,
            baseCost: baseCost
        });
    }

    /**
     * Test the `GasUtils.txBaseCost` method.
     */
    function test_txBaseCost() external view {
        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: address(0x1111111111111111111111111111111111111111).toSender(false),
            srcNetwork: 1234,
            dest: address(0x2222222222222222222222222222222222222222),
            destNetwork: 1337,
            gasLimit: 0,
            salt: 0,
            data: hex"00"
        });
        Signature memory sig = sign(gmp);

        // Check if `IExecutor.execute` match the expected base cost
        (uint256 baseCost, uint256 nonZeros, uint256 zeros) = mock.execute(sig, gmp);
        assertEq(baseCost, 24444, "Wrong calldata gas cost");
        assertEq(nonZeros, 147, "wrong number of non-zeros");
        assertEq(zeros, 273, "wrong number of zeros");
    }

    /**
     * @dev Compare the estimated gas cost VS the actual gas cost of the `execute` method.
     */
    function test_baseExecutionCost(uint16 messageSize, uint16 gasLimit) external {
        vm.assume(gasLimit >= 5000);
        vm.assume(messageSize <= (0x6000 - 32));
        messageSize += 32;
        console.log("messageSize:", messageSize);
        console.log("   gasLimit:", gasLimit);
        vm.txGasPrice(1);
        address sender = TestUtils.createTestAccount(100 ether);

        // Build the GMP message
        GmpMessage memory gmp;
        Signature memory sig;
        CallOptions memory ctx;
        (gmp, sig, ctx) = _buildGmpMessage(sender, gasLimit, gasLimit, messageSize);

        // Increase the gas limit to avoid out-of-gas errors
        ctx.gasLimit = ctx.gasLimit.saturatingAdd(10_000_000);

        // Execute the GMP message
        {
            bytes32 gmpId = gmp.eip712TypedHash(_dstDomainSeparator);
            vm.expectEmit(true, true, true, true);
            emit IExecutor.GmpExecuted(gmpId, gmp.source, gmp.dest, GmpStatus.SUCCESS, bytes32(uint256(gasLimit)));
            uint256 balanceBefore = ctx.from.balance;
            (GmpStatus status, bytes32 result) = ctx.execute(sig, gmp);
            assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "GMP execution failed");
            assertEq(result, bytes32(uint256(gasLimit)), "unexpected result");
            assertEq(balanceBefore, ctx.from.balance, "Balance should not change");
        }

        // Calculate the expected base cost
        uint256 dynamicCost =
            GasUtils.computeExecutionRefund(uint16(gmp.data.length), gmp.gasLimit) - GasUtils.EXECUTION_BASE_COST;
        uint256 expectedBaseCost = ctx.executionCost - dynamicCost;
        assertEq(expectedBaseCost, GasUtils.EXECUTION_BASE_COST, "Wrong EXECUTION_BASE_COST");
    }

    function test_gasUtils() external pure {
        uint256 baseCost = GasUtils.EXECUTION_BASE_COST;
        assertEq(GasUtils.estimateGas(0, 0, 0), 31783 + baseCost);
        assertEq(GasUtils.estimateGas(0, 33, 0), 32155 + baseCost);
        assertEq(GasUtils.estimateGas(33, 0, 0), 32815 + baseCost);
        assertEq(GasUtils.estimateGas(20, 13, 0), 32555 + baseCost);

        UFloat9x56 one = UFloatMath.ONE;
        assertEq(GasUtils.estimateWeiCost(one, 0, 0, 0, 0), 31783 + baseCost);
        assertEq(GasUtils.estimateWeiCost(one, 0, 0, 33, 0), 32155 + baseCost);
        assertEq(GasUtils.estimateWeiCost(one, 0, 33, 0, 0), 32815 + baseCost);
        assertEq(GasUtils.estimateWeiCost(one, 0, 20, 13, 0), 32555 + baseCost);

        UFloat9x56 two = UFloat9x56.wrap(0x8080000000000000);
        assertEq(GasUtils.estimateWeiCost(two, 0, 0, 0, 0), (31783 + baseCost) * 2);
        assertEq(GasUtils.estimateWeiCost(two, 0, 0, 33, 0), (32155 + baseCost) * 2);
        assertEq(GasUtils.estimateWeiCost(two, 0, 33, 0, 0), (32815 + baseCost) * 2);
        assertEq(GasUtils.estimateWeiCost(two, 0, 20, 13, 0), (32555 + baseCost) * 2);
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
