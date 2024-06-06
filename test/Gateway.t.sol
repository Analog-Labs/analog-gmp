// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Gateway.t.sol)

pragma solidity >=0.8.0;

import {Signer} from "frost-evm/sol/Signer.sol";
import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "./TestUtils.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {GasUtils} from "../src/utils/GasUtils.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {IExecutor} from "../src/interfaces/IExecutor.sol";
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

contract SigUtilsTest is GatewayEIP712, Test {
    using PrimitiveUtils for GmpMessage;

    constructor() GatewayEIP712(69, address(0)) {}

    function testPayload() public view {
        GmpMessage memory gmp = GmpMessage({
            source: GmpSender.wrap(0x0),
            srcNetwork: 42,
            dest: address(0x0),
            destNetwork: 69,
            gasLimit: 0,
            salt: 0,
            data: ""
        });
        bytes32 typedHash = gmp.eip712TypedHash(DOMAIN_SEPARATOR);
        bytes32 expected = keccak256(
            hex"19013e3afdf794f679fcbf97eba49dbe6b67cec6c7d029f1ad9a5e1a8ffefa8db2724ed044f24764343e77b5677d43585d5d6f1b7618eeddf59280858c68350af1cd"
        );
        assertEq(typedHash, expected);
    }
}

struct CallOptions {
    address from;
    address to;
    uint256 value;
    uint256 gasLimit;
    uint256 executionCost;
    uint256 baseCost;
}

library GatewayUtils {
    function execute(CallOptions memory ctx, Signature memory signature, GmpMessage memory message)
        internal
        returns (GmpStatus status, bytes32 result)
    {
        bytes memory encodedCall = abi.encodeCall(IExecutor.execute, (signature, message));
        (uint256 executionCost, uint256 baseCost, bytes memory output) =
            TestUtils.executeCall(ctx.from, ctx.to, ctx.gasLimit, encodedCall);

        ctx.executionCost = executionCost;
        ctx.baseCost = baseCost;
        if (output.length == 64) {
            assembly {
                let ptr := add(output, 32)
                status := mload(ptr)
                result := mload(add(ptr, 32))
            }
        }
    }

    function submitMessage(CallOptions memory ctx, GmpMessage memory gmp) internal returns (bytes32 result) {
        bytes memory encodedCall =
            abi.encodeCall(IGateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
        (uint256 executionCost, uint256 baseCost, bytes memory output) =
            TestUtils.executeCall(ctx.from, ctx.to, ctx.gasLimit, encodedCall);
        ctx.executionCost = executionCost;
        ctx.baseCost = baseCost;
        if (output.length == 32) {
            assembly {
                result := mload(add(output, 32))
            }
        }
    }

    function computeGmpGasCost(Signature memory signature, GmpMessage memory message)
        internal
        pure
        returns (uint256 baseCost, uint256 executionCost)
    {
        (, executionCost) = GasUtils.executionGasCost(message.data.length);
        bytes memory encodedCall = abi.encodeCall(IExecutor.execute, (signature, message));
        baseCost = TestUtils.calculateBaseCost(encodedCall);
    }
}

contract GatewayBase is Test {
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

    uint256 private constant SUBMIT_GAS_COST = 6098;
    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;
    uint8 private constant GMP_STATUS_SUCCESS = 1;

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

        vm.stopPrank();
    }

    function setUp() public {
        // check block gas limit as gas left
        assertEq(block.gaslimit, 30_000_000);
        assertTrue(gasleft() >= 10_000_000);

        // Obs: This is a special contract that wastes an exact amount of gas you send to it, helpful for testing GMP refunds and gas limits.
        // See the file `HelperContract.opcode` for more details.
        {
            bytes memory bytecode =
                hex"603b80600c6000396000f3fe5a600201803d523d60209160643560240135146018575bfd5b60345a116018575a604803565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5bf3";
            receiver = IGmpReceiver(TestUtils.deployContract(bytecode));
        }
    }

    function sign(GmpMessage memory gmp) internal view returns (Signature memory) {
        uint256 hash = uint256(gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR()));
        (uint256 e, uint256 s) = signer.signPrehashed(hash, nonce);
        return Signature({xCoord: signer.xCoord(), e: e, s: s});
    }

    function test_DepositRevertsOutOfFunds() external {
        address sender = TestUtils.createTestAccount(0);
        vm.prank(sender, sender);
        vm.expectRevert();
        gateway.deposit{value: 1}(sender.toSender(false), 0);
    }

    function test_DepositReducesSenderFunds() public {
        uint256 amount = 100 ether;
        address sender = TestUtils.createTestAccount(amount);
        uint256 balanceBefore = address(sender).balance;
        vm.prank(sender, sender);
        gateway.deposit{value: amount}(sender.toSender(false), SRC_NETWORK_ID);
        uint256 balanceAfter = address(sender).balance;
        uint256 expectedBalance = balanceBefore - amount;
        assertEq(balanceAfter, expectedBalance, "deposit failed to transfer amount from sender");
    }

    function test_DepositIncreasesGatewayFunds() external {
        uint256 amount = 100 ether;
        address sender = TestUtils.createTestAccount(amount);
        address gatewayAddress = address(gateway);
        assert(gatewayAddress != sender);
        uint256 balanceBefore = gatewayAddress.balance;
        vm.prank(sender, sender);
        gateway.deposit{value: amount}(sender.toSender(false), SRC_NETWORK_ID);
        uint256 balanceAfter = gatewayAddress.balance;
        uint256 expectedBalance = balanceBefore + amount;
        assertEq(balanceAfter, expectedBalance, "deposit failed to transfer amount to gateway");
    }

    function test_Receiver() external {
        bytes memory testEncodedCall = abi.encodeCall(
            IGmpReceiver.onGmpReceived,
            (
                0x0000000000000000000000000000000000000000000000000000000000000000,
                1,
                0x0000000000000000000000000000000000000000000000000000000000000000,
                abi.encode(uint256(1234))
            )
        );
        // Calling the receiver contract directly to make the address warm
        address sender = TestUtils.createTestAccount(10 ether);
        (uint256 gasUsed,, bytes memory output) =
            TestUtils.executeCall(sender, address(receiver), 23_318, testEncodedCall);
        assertEq(gasUsed, 1234);
        assertEq(output.length, 32);
    }

    function test_gasMeter() external {
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
            data: new bytes(65)
        });
        Signature memory sig = sign(gmp);

        // Calculate memory expansion cost and base cost
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);

        // Deposit funds
        {
            GmpSender gmpSender = sender.toSender(false);
            assertEq(gateway.depositOf(gmpSender, SRC_NETWORK_ID), 0);
            vm.prank(sender, sender);
            gateway.deposit{value: (baseCost + executionCost) * 10000}(gmpSender, SRC_NETWORK_ID);
            assertEq(gateway.depositOf(gmpSender, SRC_NETWORK_ID), (baseCost + executionCost) * 10000);
        }

        // Transaction Parameters
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: baseCost + executionCost + 2160 + 693,
            executionCost: 0,
            baseCost: 0
        });

        GmpStatus status;
        bytes32 returned;

        // Expect a revert
        vm.expectRevert("insufficient gas to execute GMP message");
        (status, returned) = ctx.execute(sig, gmp);

        // Give sufficient gas
        ctx.gasLimit += 1;

        // Execute GMP message first time (which have 4500 gas overhead)
        (status, returned) = ctx.execute(sig, gmp);
        assertEq(returned, bytes32(0), "GMP result stored doesn't match the returned result");
        assertEq(executionCost, ctx.executionCost, "executionCost != ctx.executionCost");
        assertEq(baseCost, ctx.baseCost, "baseCost != ctx.baseCost");
        assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "Unexpected GMP status");
    }

    function test_depositMapping() external {
        vm.txGasPrice(1);
        address sender = TestUtils.createTestAccount(100 ether);

        // GMP message gas used
        uint256 gmpGasLimit = 1_000;

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gmpGasLimit,
            salt: 1,
            data: abi.encodePacked(gmpGasLimit)
        });
        Signature memory sig = sign(gmp);
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);

        // Deposit funds
        {
            GmpSender gmpSender = sender.toSender(false);
            assertEq(gateway.depositOf(gmpSender, SRC_NETWORK_ID), 0);
            vm.prank(sender, sender);
            // uint256 deposit = baseCost + executionCost + gmpGasLimit + 3440;
            uint256 deposit = baseCost + executionCost + gmpGasLimit;
            gateway.deposit{value: deposit}(gmpSender, SRC_NETWORK_ID);
            assertEq(gateway.depositOf(gmpSender, SRC_NETWORK_ID), deposit);
        }

        // Execute GMP message
        uint256 beforeBalance = sender.balance;
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: baseCost + executionCost + 2160 + 725 + 955,
            executionCost: 0,
            baseCost: 0
        });
        {
            (GmpStatus status, bytes32 returned) = ctx.execute(sig, gmp);
            assertEq(returned, bytes32(gmpGasLimit), "unexpected GMP result");

            // Verify the GMP message status
            assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "Unexpected GMP status");
            Gateway.GmpInfo memory info = gateway.gmpInfo(gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR()));
            assertEq(
                uint256(info.status), uint256(GmpStatus.SUCCESS), "GMP status stored doesn't match the returned status"
            );

            // Verify the gas cost
            assertEq(ctx.executionCost, executionCost + gmpGasLimit, "unexpected gas used");
        }

        // Verify the gas refund
        uint256 afterBalance = sender.balance;
        assertEq(beforeBalance, afterBalance, "wrong refund amount, before != after");
        assertEq(gateway.depositOf(sender.toSender(false), SRC_NETWORK_ID), 0, "discount wrong amount from deposit");
    }

    function test_refund() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(100 ether).toSender(false);

        // GMP message gas used
        uint256 gmpGasUsed = 1_000;

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender,
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gmpGasUsed,
            salt: 1,
            data: abi.encodePacked(uint256(gmpGasUsed))
        });
        Signature memory sig = sign(gmp);

        // Deposit funds
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);
        uint256 expectGasUsed = baseCost + executionCost + gmp.gasLimit;
        uint256 deposit = expectGasUsed * 3;
        gateway.deposit{value: deposit}(sender, SRC_NETWORK_ID);

        // Calculate memory expansion cost and base cost
        // uint256 baseCost;
        // {
        //     bytes memory encodedExecuteCall = abi.encodeCall(IExecutor.execute, (sig, gmp));
        //     baseCost = TestUtils.calculateBaseCost(encodedExecuteCall);
        //     expectGasUsed += TestUtils.memExpansionCost(encodedExecuteCall.length);
        // }

        // Deposit funds
        // {
        //     GmpSender gmpSender = sender.toSender(false);
        //     assertEq(gateway.depositOf(gmpSender, DEST_NETWORK_ID), 0);
        //     vm.prank(sender, sender);
        //     gateway.deposit{value: expectGasUsed + baseCost}(gmpSender, DEST_NETWORK_ID);
        //     assertEq(gateway.depositOf(gmpSender, DEST_NETWORK_ID), expectGasUsed + baseCost);
        // }

        // Execute GMP message
        uint256 beforeBalance = sender.toAddress().balance;
        CallOptions memory ctx = CallOptions({
            from: sender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: expectGasUsed + 2160 + 785 + 10,
            executionCost: 0,
            baseCost: 0
        });
        {
            (GmpStatus status, bytes32 returned) = ctx.execute(sig, gmp);

            // Verify the GMP message status
            assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "Unexpected GMP status");
            Gateway.GmpInfo memory info = gateway.gmpInfo(gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR()));
            assertEq(
                uint256(info.status), uint256(GmpStatus.SUCCESS), "GMP status stored doesn't match the returned status"
            );
            assertEq(returned, bytes32(gmp.gasLimit), "unexpected GMP result");

            // Verify the gas cost
            assertEq(ctx.executionCost + ctx.baseCost, expectGasUsed, "unexpected gas used");
        }

        // Verify the gas refund
        uint256 afterBalance = sender.toAddress().balance;
        assertEq(beforeBalance, afterBalance, "wrong refund amount");
        assertEq(gateway.depositOf(sender, DEST_NETWORK_ID), 0, "discount wrong amount from deposit");
    }

    function test_ExecuteRevertsWrongNetwork() external {
        vm.txGasPrice(1);
        uint256 amount = 10 ether;
        address sender = TestUtils.createTestAccount(amount * 2);

        gateway.deposit{value: amount}(sender.toSender(false), SRC_NETWORK_ID);
        GmpMessage memory wrongNetwork = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(0x0),
            destNetwork: SRC_NETWORK_ID,
            gasLimit: 1000,
            salt: 1,
            data: ""
        });
        Signature memory wrongNetworkSig = sign(wrongNetwork);
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: 1_000_000,
            executionCost: 0,
            baseCost: 0
        });
        vm.expectRevert("invalid gmp network");
        ctx.execute(wrongNetworkSig, wrongNetwork);
    }

    function test_wrongSource() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(100 ether).toSender(false);
        gateway.deposit{value: 10 ether}(sender, SRC_NETWORK_ID);
        GmpMessage memory gmp = GmpMessage({
            source: GmpSender.wrap(0x0),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(0),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1000,
            salt: 1,
            data: ""
        });
        Signature memory sig = sign(gmp);

        // Deposit funds
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);
        uint256 deposit = (baseCost + executionCost + gmp.gasLimit) * 3;
        gateway.deposit{value: deposit}(sender, SRC_NETWORK_ID);

        CallOptions memory ctx = CallOptions({
            from: sender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: baseCost + executionCost + gmp.gasLimit + 100_000,
            executionCost: 0,
            baseCost: 0
        });
        (GmpStatus status, bytes32 result) = ctx.execute(sig, gmp);
        assertEq(uint256(status), uint256(GmpStatus.INSUFFICIENT_FUNDS), "unexpected GMP status");
        assertEq(result, bytes32(0), "unexpected GMP result");
    }

    function test_gmpStatusFailedWithoutDeposit() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(100 ether).toSender(false);
        assertEq(gateway.depositOf(sender, SRC_NETWORK_ID), 0);

        GmpMessage memory gmp = GmpMessage({
            source: sender,
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1_000_000,
            salt: 1,
            data: abi.encode(uint256(1_000_000))
        });
        Signature memory sig = sign(gmp);

        // execute gmp message
        CallOptions memory ctx = CallOptions({
            from: sender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: 1_500_000,
            executionCost: 0,
            baseCost: 0
        });
        (GmpStatus status, bytes32 result) = ctx.execute(sig, gmp);
        assertEq(uint256(status), uint256(GmpStatus.INSUFFICIENT_FUNDS), "unexpected GMP status");
        assertEq(result, bytes32(0), "unexpected GMP result");
    }

    function test_executeRevertsBelowDeposit() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(100 ether).toSender(false);

        GmpMessage memory gmp = GmpMessage({
            source: sender,
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1000,
            salt: 1,
            data: abi.encode(uint256(10_000))
        });
        Signature memory sig = sign(gmp);

        // Deposit funds
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);
        uint256 insufficientDeposit = baseCost + executionCost + gmp.gasLimit - 1;
        gateway.deposit{value: insufficientDeposit}(sender, SRC_NETWORK_ID);

        // Execute GMP message
        CallOptions memory ctx = CallOptions({
            from: sender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: 100_000,
            executionCost: 0,
            baseCost: 0
        });
        (GmpStatus status, bytes32 result) = ctx.execute(sig, gmp);
        assertEq(uint256(GmpStatus.INSUFFICIENT_FUNDS), uint256(status), "unexpected GMP status");
        assertEq(result, bytes32(0), "unexpected GMP result");
        assertLe(ctx.executionCost, executionCost, "unexpected execution cost");
        assertEq(ctx.baseCost, baseCost, "unexpected base cost");
    }

    function test_ExecuteRevertsBelowGasLimit() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(100 ether).toSender(false);
        GmpMessage memory gmp = GmpMessage({
            source: sender,
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100_000,
            salt: 1,
            data: abi.encode(uint256(100_000))
        });
        Signature memory sig = sign(gmp);

        // Deposit funds
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);
        uint256 deposit = (baseCost + executionCost + gmp.gasLimit) * 2;
        gateway.deposit{value: deposit}(sender, SRC_NETWORK_ID);

        // Execute GMP message
        CallOptions memory ctx = CallOptions({
            from: sender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: baseCost + executionCost,
            executionCost: 0,
            baseCost: 0
        });
        vm.expectRevert("insufficient gas to execute GMP message");
        ctx.execute(sig, gmp);
    }

    function test_executeRevertsAlreadyExecuted() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(1000 ether).toSender(false);
        GmpMessage memory gmp = GmpMessage({
            source: sender,
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 1000,
            salt: 1,
            data: abi.encode(uint256(1000))
        });
        Signature memory sig = sign(gmp);

        // Deposit funds
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);
        uint256 deposit = (baseCost + executionCost + gmp.gasLimit) * 3;
        gateway.deposit{value: deposit}(sender, SRC_NETWORK_ID);

        // Execute GMP message first time
        CallOptions memory ctx = CallOptions({
            from: sender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: 1_000_000,
            executionCost: 0,
            baseCost: 0
        });
        (GmpStatus status, bytes32 result) = ctx.execute(sig, gmp);
        assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "unexpected GMP status");
        assertEq(gmp.gasLimit, uint256(result), "unexpected GMP result");

        // Execute GMP message second time
        vm.expectRevert("message already executed");
        ctx.execute(sig, gmp);
    }

    function testSubmitGmpMessage() external {
        vm.txGasPrice(1);
        GmpSender gmpSender = TestUtils.createTestAccount(1000 ether).toSender(false);
        GmpMessage memory gmp = GmpMessage({
            source: gmpSender,
            srcNetwork: DEST_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100000,
            salt: 0,
            data: abi.encodePacked(uint256(100_000))
        });
        bytes32 id = gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR());

        // Check the previous message hash
        assertEq(gateway.prevMessageHash(), bytes32(uint256(2 ** 256 - 1)), "WROONNGG");

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );

        // Submit GMP message
        bytes memory encodedCall =
            abi.encodeCall(Gateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
        (uint256 execution, uint256 base, bytes memory output) =
            TestUtils.executeCall(gmpSender.toAddress(), address(gateway), 100_000, encodedCall);
        assertEq(output.length, 32, "unexpected gateway.submitMessage output");

        // Verify the gas cost
        uint256 expectedCost = SUBMIT_GAS_COST + 2800 + 2000;
        assertEq(execution, expectedCost, "unexpected execution gas cost");

        // Now the second GMP message should have the salt equals to previous gmp hash
        gmp.salt = uint256(id);
        id = gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR());

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );

        // Submit GMP message
        encodedCall = abi.encodeCall(Gateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
        (execution, base, output) = TestUtils.executeCall(gmpSender.toAddress(), address(gateway), 100_000, encodedCall);
        assertEq(output.length, 32, "unexpected gateway.submitMessage output");

        // Verify the gas cost
        expectedCost = SUBMIT_GAS_COST;
        assertEq(execution, expectedCost, "unexpected execution gas cost");

        // Now the second GMP message should have the salt equals to previous gmp hash
        gmp.salt = uint256(id);
        id = gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR());

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );

        // Submit GMP message
        encodedCall = abi.encodeCall(Gateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
        (execution, base, output) = TestUtils.executeCall(gmpSender.toAddress(), address(gateway), 100_000, encodedCall);
        assertEq(output.length, 32, "unexpected gateway.submitMessage output");
        // Verify the gas cost
        expectedCost = SUBMIT_GAS_COST;
        assertEq(execution, expectedCost, "unexpected execution gas cost");
    }
}

/**
 * @dev Workaround to fix Forge gas report.
 *
 * Due to limitations in forge, the gas cost reported is misleading:
 * - https://github.com/foundry-rs/foundry/issues/6578
 * - https://github.com/foundry-rs/foundry/issues/6910
 *
 * This contract is a workaround that fixes it by inject an arbitrary code into the `GatewayBase`,
 * it replaces the constant `0x7E7E7E7E7E7E...` defined in the `_call` function by the `INLINE_BYTECODE`.
 * This allow us to precisely compute the execution gas cost.
 *
 * This workaround is necessary while solidity doesn't add support to verbatim in inline assembly code.
 * - https://github.com/ethereum/solidity/issues/12067
 *
 * @author Lohann Ferreira
 */
contract GatewayTest is GatewayBase {
    /**
     * @dev Bytecode that does an acurrate gas measurement of a call, it is equivalent to:
     * ```solidity
     * uint256 gasBefore = gasleft();
     * contract.call{gas: gasLimit}(data);
     * uint256 gasAfter = gasleft();
     * uint256 gasUsed = gasBefore - gasAfter - OVERHEAD;
     * assembly {
     *    mstore(mload(0x40), gasUsed)
     * }
     * ```
     * Solidity is a black box, is not possible to reliably calculate the `OVERHEAD` cost, creating a lot of
     * uncertainty in the gas measurements. `Yul` have the same issue once we don't control the EVM stack.
     * This code workaround this by doing the gas measurement right before and after execute the CALL opcode.
     */
    bytes32 private constant INLINE_BYTECODE = 0x670000000000000000813f50919594939291905a96f15a606901909103600052;

    constructor() payable {
        // In solidity the child's constructor are executed before the parent's constructor,
        // so once this contract extends `GatewayBase`, it's constructor is executed first.

        // Copy `GatewayBase` runtime code into memory.
        bytes memory runtimeCode = type(GatewayBase).runtimeCode;

        // Replaces the first occurence of `0x7E7E..` in the runtime code by the `INLINE_BYTECODE`
        /// @solidity memory-safe-assembly
        assembly {
            let size := mload(runtimeCode)
            let i := add(runtimeCode, 32)

            // Efficient Algorithm to find 32 consecutive repeated bytes in a byte sequence
            for {
                let chunk := 1
                let end := add(i, size)
            } gt(chunk, 0) { i := add(i, chunk) } {
                // Transform all `0x7E` bytes into `0xFF`
                // 0x81 ^ 0x7E == 0xFF
                // Also transform all other bytes in something different than `0xFF`
                chunk := xor(mload(i), 0x8181818181818181818181818181818181818181818181818181818181818181)

                // Find the right most unset bit, which is equivalent to find the
                // right most byte different than `0x7E`.
                // ex: (0x12345678FFFFFF + 1) & (~0x12345678FFFFFF) == 0x00000001000000
                chunk := and(add(chunk, 1), not(chunk))

                // Round down to the closest multiple of 256
                // Ex: 2 ** 18 become 2 ** 16
                chunk := div(chunk, mod(chunk, 0xff))

                // Find the number of leading bytes different than `0x7E`.
                // Rationale:
                // Multiplying a number by a power of 2 is the same as shifting the bits to the left
                // 1337 * (2 ** 16) == 1337 << 16
                // Once the chunk is a multiple of 256 it always shift entire bytes, we use this to
                // select a specific byte in a byte sequence.
                chunk := shr(248, mul(0x201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201, chunk))

                // Stop the loop if we go out of bounds
                chunk := mul(chunk, lt(i, end))
            }

            // Check if we found the 32 byte constant `7E7E7E...`
            if not(xor(mload(i), 0x8181818181818181818181818181818181818181818181818181818181818181)) {
                let ptr := mload(0x40)
                mstore(ptr, shl(224, 0x08c379a0))
                mstore(add(ptr, 4), 32) // message offset
                mstore(add(ptr, 36), 29) // message size
                mstore(add(ptr, 68), "Failed to inject the bytecode")
                revert(ptr, 100)
            }

            // Replace the runtime code with the injected bytecode
            mstore(add(i, 1), 0x5B)
            mstore(i, INLINE_BYTECODE)

            // Return the modified runtime code
            return(add(runtimeCode, 32), mload(runtimeCode))
        }
    }
}
