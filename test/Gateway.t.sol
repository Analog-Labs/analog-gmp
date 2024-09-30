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

contract ParseCall {
    function execute(Signature calldata signature, GmpMessage calldata message)
        external
        pure
        returns (Signature memory sig, GmpMessage memory gmp)
    {
        return (signature, message);
    }
}

library GatewayUtils {
    function execute(CallOptions memory ctx, Signature memory signature, GmpMessage memory message)
        internal
        returns (GmpStatus status, bytes32 result)
    {
        bytes memory encodedCall = abi.encodeCall(IExecutor.execute, (signature, message));
        (uint256 executionCost, uint256 baseCost, bytes memory output) =
            TestUtils.executeCall(ctx.from, ctx.to, ctx.gasLimit, ctx.value, encodedCall);

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
            TestUtils.executeCall(ctx.from, ctx.to, ctx.gasLimit, ctx.value, encodedCall);
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
        executionCost = GasUtils.computeExecutionRefund(uint16(message.data.length), 0);
        bytes memory encodedCall = abi.encodeCall(IExecutor.execute, (signature, message));
        baseCost = TestUtils.calculateBaseCost(encodedCall);
    }

    // Computes the EIP-712 domain separador
    function computeDomainSeparator(uint256 networkId, address addr) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Analog Gateway Contract"),
                keccak256("0.1.0"),
                uint256(networkId),
                address(addr)
            )
        );
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

    // Domain Separators
    bytes32 private _srcDomainSeparator;
    bytes32 private _dstDomainSeparator;

    uint256 private constant SUBMIT_GAS_COST = 15034;
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
        vm.deal(address(gateway), 100 ether);

        _srcDomainSeparator = GatewayUtils.computeDomainSeparator(SRC_NETWORK_ID, address(gateway));
        _dstDomainSeparator = GatewayUtils.computeDomainSeparator(DEST_NETWORK_ID, address(gateway));

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
                hex"603c80600a5f395ff3fe5a600201803d523d60209160643560240135146018575bfd5b60365a116018575a604903565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5bf3";
            receiver = IGmpReceiver(TestUtils.deployContract(bytecode));
        }
    }

    function test_jose() external {
        // TssKey[] memory shards = new TssKey[](1);
        // // shards[0] = TssKey({yParity: 1, xCoord: 0x4f475ae68e3f41e2357ae70d5e682b209b5ddc8bf1867020665383a3279e5c56});
        // shards[0] = TssKey({yParity: 0, xCoord: 0x92f7a73cb66244cecce2be61714de3e16f07552261db819c912f64086b5d452e});
        // bytes memory data = abi.encodeCall(Gateway.sudoRemoveShards, (shards));
        // console.logBytes(data);

        // Build and sign GMP message
        // address sender = TestUtils.createTestAccount(10 ether);
        // GmpMessage memory gmp = GmpMessage({
        //     source: sender.toSender(false),
        //     srcNetwork: SRC_NETWORK_ID,
        //     dest: address(bytes20(keccak256("dummy_address"))),
        //     destNetwork: DEST_NETWORK_ID,
        //     gasLimit: 0,
        //     salt: 0,
        //     data: hex"deadbeef"
        // });
        // Signature memory sig = sign(gmp);
        // bytes memory data = abi.encodeCall(Gateway.execute, (sig, gmp));
        // console.logBytes(data);

        bytes memory txData =
            hex"bdfbbea64f475ae68e3f41e2357ae70d5e682b209b5ddc8bf1867020665383a3279e5c565f0989669c1aadbc077735a4b1fe35393ef49446a55023745468acddcb9c0df237c3f5a3983ed86bc6cff1c8259d0d0f0731a27c36e0d76db0fbcb58b82e42400000000000000000000000000000000000000000000000000000000000000080000000000000000000000001585bf6223f90a0852595b4a2bbfb33c4fe4fda90000000000000000000000000000000000000000000000000000000000000000500000000000000000000000013f46181b6d840c18f968757b6b3aeb798c98d32000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000186a0fb324bf098943b1f04b7a394392e1ed7a4e5b5ac57a625ef9019a0e1b4c4b6a200000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001";
        txData =
            hex"bdfbbea6f61541773a756d2a16eb91570d9b0f892bc113db02eb9e9268a5002f8498973b38c3c5d0f276f36e64705f627d2eeca781a9f44b11bcf5488c9ed1a5778233766565964e61b87c739b36abd8d0f74d5f17eff5158c4b0f8d9df02b1ee85cd69e0000000000000000000000000000000000000000000000000000000000000080000000000000000000000001e907ef1cf0a5eb4e23d8ae0a3b1075475566dee300000000000000000000000000000000000000000000000000000000000000050000000000000000000000000890e5d8771f575eb7f4ef083401dd6682e5d1c9000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000493e04aa80e2c774ebfb3419d0e8b35ada8cceae8b5c8f4f48913c0a775392f4fb4c600000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001";
        ParseCall parser = new ParseCall();
        bool success;
        bytes memory result;
        (success, result) = address(parser).call(txData);
        assembly {
            if iszero(success) { revert(add(result, 0x20), mload(result)) }
        }
        GmpMessage memory gmp;
        Signature memory sig;
        (sig, gmp) = abi.decode(result, (Signature, GmpMessage));
        bytes32 messageId;
        {
            bytes32 domainSeparator =
                GatewayUtils.computeDomainSeparator(gmp.destNetwork, 0x000000007f56768dE3133034FA730a909003a165);
            messageId = gmp.eip712TypedHash(domainSeparator);
        }

        string memory obj1 = "gmp.source";
        {
            bool isContract = (uint256(GmpSender.unwrap(gmp.source)) >> 160) > 0;
            vm.serializeAddress(obj1, "address", gmp.source.toAddress());
            obj1 = vm.serializeBool(obj1, "is_contract", isContract);
        }

        string memory obj2 = "gmp";
        vm.serializeBytes32(obj2, "id", messageId);
        vm.serializeString(obj2, "source", obj1);
        vm.serializeUint(obj2, "srcNetwork", gmp.srcNetwork);
        vm.serializeAddress(obj2, "dest", gmp.dest);
        vm.serializeUint(obj2, "dstNetwork", gmp.destNetwork);
        vm.serializeUint(obj2, "gasLimit", gmp.gasLimit);
        vm.serializeBytes32(obj2, "salt", bytes32(gmp.salt));
        obj2 = vm.serializeBytes(obj2, "data", gmp.data);

        obj1 = "signature";
        vm.serializeBytes32(obj1, "xCoord", bytes32(sig.xCoord));
        vm.serializeBytes32(obj1, "e", bytes32(sig.e));
        obj1 = vm.serializeBytes32(obj1, "s", bytes32(sig.s));

        string memory obj3 = "final";
        vm.serializeString(obj3, "signature", obj1);
        obj3 = vm.serializeString(obj3, "message", obj2);

        emit log_named_string("gmp", obj3);

        emit log_named_bytes32("sig.x", bytes32(sig.xCoord));
        emit log_named_bytes32("sig.e", bytes32(sig.e));
        emit log_named_bytes32("sig.s", bytes32(sig.s));

        emit log_named_bytes32("gmp.id", messageId);
        emit log_named_address("gmp.source.address", gmp.source.toAddress());
        emit log_named_uint("gmp.source.contract", uint256(GmpSender.unwrap(gmp.source)) >> 160);
        emit log_named_uint("gmp.srcNetwork", gmp.srcNetwork);
        emit log_named_address("gmp.dest", gmp.dest);
        emit log_named_uint("gmp.dstNetwork", gmp.destNetwork);
        emit log_named_uint("gmp.gasLimit", gmp.gasLimit);
        emit log_named_bytes32("gmp.salt", bytes32(gmp.salt));
        emit log_named_bytes("gmp.data", gmp.data);
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
            TestUtils.executeCall(sender, address(receiver), 23_318, 0, testEncodedCall);
        assertEq(gasUsed, 1234);
        assertEq(output.length, 32);
    }

    function test_estimateMessageCost() external {
        vm.txGasPrice(1);
        uint256 cost = gateway.estimateMessageCost(DEST_NETWORK_ID, 96, 100000);
        assertEq(cost, 178501);
    }

    function test_checkPayloadSize() external {
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
            data: new bytes(24576 + 1)
        });

        Signature memory sig = sign(gmp);

        // Calculate memory expansion cost and base cost
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);

        // Transaction Parameters
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit) + baseCost + 1_000_000,
            executionCost: 0,
            baseCost: 0
        });

        GmpStatus status;
        bytes32 returned;

        // Expect a revert
        vm.expectRevert("msg data too large");
        (status, returned) = ctx.execute(sig, gmp);
        assertLt(ctx.executionCost, executionCost, "revert should use less gas!!");
        assertEq(ctx.baseCost, baseCost, "unexpected base cost");
    }

    /**
     * @dev Test the gas metering for the `execute` function.
     */
    function test_gasMeter(uint16 messageSize) external {
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
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);

        // Transaction Parameters
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit) + baseCost - 1,
            executionCost: 0,
            baseCost: 0
        });

        GmpStatus status;
        bytes32 returned;

        // Expect a revert
        vm.expectRevert();
        (status, returned) = ctx.execute(sig, gmp);

        // Check if the gateway has enough balance to refund the gas
        uint256 gatewayBalance = address(gateway).balance;
        uint256 senderBalance = address(sender).balance;
        assertGe(gatewayBalance, executionCost + baseCost);
        assertGe(senderBalance, ctx.gasLimit + ctx.value);

        // Give sufficient gas
        ctx.gasLimit += 1;
        (status, returned) = ctx.execute(sig, gmp);

        assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "gmp execution failed");
        assertEq(uint256(returned), gmp.gasLimit, "wrong gmp return value");
        assertEq(ctx.baseCost, baseCost, "ctx.baseCost != baseCost");
        assertEq(ctx.executionCost, executionCost, "ctx.executionCost != executionCost");
        assertEq(gatewayBalance - address(gateway).balance, executionCost + baseCost, "wrong refund amount");
        assertEq(senderBalance, address(sender).balance, "sender balance should not change");
        assertEq(
            ctx.gasLimit - baseCost, GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit), "gas needed mismatch"
        );

        // Submit GMP message
        {
            // Calculate the minimal gmp value minus one
            uint256 nonZeros = GasUtils.countNonZeros(gmp.data);
            uint256 zeros = gmp.data.length - nonZeros;
            ctx.value = GasUtils.estimateGas(uint16(nonZeros), uint16(zeros), gmp.gasLimit) - 1;

            // Add sufficient gas
            ctx.gasLimit += gmp.data.length * 8;
        }

        // Must revert if fund are insufficient
        vm.expectRevert("insufficient tx value");
        ctx.submitMessage(gmp);

        {
            bytes memory submitEncoded =
                abi.encodeCall(IGateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
            assertEq(submitEncoded.length, ((gmp.data.length + 31) & 0xffe0) + 164, "wrong encoded length");
        }

        // Must work if the funds are sufficient
        ctx.value += 1;
        ctx.submitMessage(gmp);

        assertEq(
            ctx.executionCost,
            GasUtils.submitMessageGasCost(uint16(gmp.data.length)) - 4500,
            "unexpected submit message gas cost"
        );
    }

    function test_submitMessageMeter(uint16 messageSize) external {
        vm.assume(messageSize <= 0x6000);
        vm.txGasPrice(1);
        address sender = TestUtils.createTestAccount(1000 ether);

        // Build and sign GMP message
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(false),
            srcNetwork: DEST_NETWORK_ID,
            dest: address(bytes20(keccak256("dummy_address"))),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 0,
            salt: 0,
            data: new bytes(messageSize)
        });

        // Calculate memory expansion cost and base cost
        uint256 baseCost;
        {
            bytes memory encoded =
                abi.encodeCall(IGateway.submitMessage, (gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.data));
            assertEq(encoded.length, ((gmp.data.length + 31) & 0xffe0) + 164, "wrong encoded length");
            emit log_named_bytes("    calldata", encoded);
            baseCost = TestUtils.calculateBaseCost(encoded);
        }

        // Transaction Parameters
        CallOptions memory ctx = CallOptions({
            from: sender,
            to: address(gateway),
            value: 0,
            gasLimit: GasUtils.submitMessageGasNeeded(uint16(gmp.data.length)) + baseCost,
            executionCost: 0,
            baseCost: 0
        });

        // Submit the transaction
        {
            uint256 nonZeros = GasUtils.countNonZeros(gmp.data);
            uint256 zeros = gmp.data.length - nonZeros;
            ctx.value = GasUtils.estimateGas(uint16(nonZeros), uint16(zeros), gmp.gasLimit);
        }

        uint256 snapshot = vm.snapshot();
        // Must work if the funds and gas limit are sufficient
        bytes32 id = gmp.eip712TypedHash(_dstDomainSeparator);
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );
        assertEq(ctx.submitMessage(gmp), id, "unexpected GMP id");

        // Verify the execution cost
        assertEq(
            ctx.executionCost,
            GasUtils.submitMessageGasCost(uint16(gmp.data.length)),
            "unexpected submit message gas cost"
        );

        // Must revert if fund are insufficient
        vm.revertTo(snapshot);
        ctx.value -= 1;
        vm.expectRevert("insufficient tx value");
        ctx.submitMessage(gmp);
    }

    function test_refund() external {
        vm.txGasPrice(1);
        GmpSender sender = TestUtils.createTestAccount(100 ether).toSender(false);

        // GMP message gas used
        uint256 gmpGasUsed = 2_000;

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

        // Estimate execution cost
        (uint256 baseCost, uint256 executionCost) = GatewayUtils.computeGmpGasCost(sig, gmp);
        uint256 expectGasUsed = baseCost + executionCost + gmp.gasLimit;

        // Execute GMP message
        uint256 beforeBalance = sender.toAddress().balance;
        {
            CallOptions memory ctx = CallOptions({
                from: sender.toAddress(),
                to: address(gateway),
                value: 0,
                gasLimit: GasUtils.executionGasNeeded(gmp.data.length, gmp.gasLimit) + baseCost,
                executionCost: 0,
                baseCost: 0
            });
            (GmpStatus status, bytes32 returned) = ctx.execute(sig, gmp);
            {
                VmSafe.Gas memory gas = vm.lastCallGas();
                // Verify the gas cost
                // assertEq(uint256(gas.gasTotalUsed) - executionCost, uint256(gas.gasRemaining), "unexpected gas used");
                assertEq(gas.gasTotalUsed, executionCost + 2000, "unexpected gas used");
                // assertEq(ctx.executionCost, executionCost + gmp.gasLimit, "unexpected execution cost");
            }

            // Verify the GMP message status
            assertEq(uint256(status), uint256(GmpStatus.SUCCESS), "Unexpected GMP status");
            Gateway.GmpInfo memory info = gateway.gmpInfo(gmp.eip712TypedHash(_dstDomainSeparator));
            assertEq(
                uint256(info.status), uint256(GmpStatus.SUCCESS), "GMP status stored doesn't match the returned status"
            );
            assertEq(returned, bytes32(gmp.gasLimit), "unexpected GMP result");

            // Verify the gas cost
            assertEq(ctx.executionCost + ctx.baseCost, expectGasUsed, "unexpected gas used");
            assertEq(ctx.executionCost, executionCost + gmp.gasLimit, "unexpected execution cost");
        }

        // Verify the gas refund
        uint256 afterBalance = sender.toAddress().balance;
        assertEq(beforeBalance, afterBalance, "wrong refund amount");
    }

    function test_ExecuteRevertsWrongNetwork() external {
        vm.txGasPrice(1);
        uint256 amount = 10 ether;
        address sender = TestUtils.createTestAccount(amount * 2);

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
            gasLimit: 100_000,
            salt: 0,
            data: abi.encodePacked(uint256(100_000))
        });
        bytes32 id = gmp.eip712TypedHash(_dstDomainSeparator);

        // Check the previous message hash
        assertEq(gateway.prevMessageHash(), bytes32(uint256(2 ** 256 - 1)), "wrong previous message hash");

        CallOptions memory ctx = CallOptions({
            from: gmpSender.toAddress(),
            to: address(gateway),
            value: 0,
            gasLimit: 1_000_000,
            executionCost: 0,
            baseCost: 0
        });

        // Compute GMP message price
        {
            uint16 nonZeros = uint16(GasUtils.countNonZeros(gmp.data));
            uint16 zeros = uint16(gmp.data.length) - nonZeros;
            ctx.value = GasUtils.estimateWeiCost(UFloatMath.ONE, 0, nonZeros, zeros, gmp.gasLimit);
        }

        // Submit message with insufficient funds
        ctx.value -= 1;
        vm.expectRevert("insufficient tx value");
        ctx.submitMessage(gmp);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );

        // Submit message with sufficient funds
        ctx.value += 1;
        assertEq(ctx.submitMessage(gmp), id, "unexpected GMP id");

        // Verify the gas cost
        uint256 expectedCost = GasUtils.submitMessageGasCost(uint16(gmp.data.length)) - 6500;
        assertEq(ctx.executionCost, expectedCost, "unexpected execution gas cost");

        // Now the second GMP message should have the salt equals to previous gmp hash
        gmp.salt = uint256(id);
        id = gmp.eip712TypedHash(_dstDomainSeparator);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit IGateway.GmpCreated(
            id, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );
        assertEq(ctx.submitMessage(gmp), id, "unexpected GMP id");
        assertEq(ctx.executionCost, expectedCost - 6800, "unexpected execution gas cost");
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
    // bytes32 private constant INLINE_BYTECODE = 0x670000000000000000813f50919594939291905a96f15a606901909103600052;
    bytes32 private constant INLINE_BYTECODE = 0x6000823f505a96949290959391f15a607b019091036800000000000000000052;

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
