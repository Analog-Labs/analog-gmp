// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/GasUtils.t.sol)

pragma solidity >=0.8.0;

import {Signer} from "frost-evm/sol/Signer.sol";
import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "./TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway} from "../src/Gateway.sol";
import {GasUtils} from "../src/GasUtils.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {GmpMessage, Signature, TssKey, GmpStatus, PrimitiveUtils, Batch} from "../src/Primitives.sol";

uint256 constant secret = 0x42;
uint256 constant nonce = 0x69;

contract GasUtilsMock {
    function execute(Signature calldata, GmpMessage calldata)
        external
        pure
        returns (uint256 baseCost, uint256 nonZeros, uint256 zeros)
    {
        baseCost = GasUtils.txBaseGas();
        nonZeros = GasUtils.countNonZerosCalldata(msg.data);
        zeros = msg.data.length - nonZeros;
    }
}

contract GasUtilsTest is Test {
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for address;

    VmSafe.Wallet internal admin;
    Gateway internal gateway;
    IGmpReceiver internal receiver;

    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 internal constant DEST_NETWORK_ID = 1337;

    constructor() {
        admin = vm.createWallet(secret);
        vm.deal(admin.addr, 100 ether);
        gateway = TestUtils.setupGateway(admin, DEST_NETWORK_ID);
        TestUtils.setMockShards(admin, address(gateway), admin);
        vm.deal(admin.addr, 100 ether);
        receiver = IGmpReceiver(new GasSpender());
    }

    /**
     * Test the `GasUtils.txBaseCost` method.
     */
    function test_txBaseCost() external {
        GasUtilsMock mock = new GasUtilsMock();
        GmpMessage memory gmp = GmpMessage({
            source: address(0x1111111111111111111111111111111111111111).toSender(),
            srcNetwork: 1234,
            dest: address(0x2222222222222222222222222222222222222222),
            destNetwork: 1337,
            gasLimit: 0,
            nonce: 0,
            data: hex"00"
        });
        Signature memory sig = Signature({xCoord: type(uint256).max, e: type(uint256).max, s: type(uint256).max});
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
        address sender = address(0xdead_beef);
        vm.deal(sender, 10 ether);

        bytes memory data = new bytes(messageSize);
        address gmpReceiver;
        if (gasLimit > 0) {
            gmpReceiver = address(receiver);
            assembly {
                mstore(add(data, 32), gasLimit)
            }
        } else {
            // Create a new unique receiver address for each message, otherwise the gas refund will not work.
            gmpReceiver = address(bytes20(keccak256(abi.encode(sender, gasLimit, messageSize))));
        }
        GmpMessage memory gmp = GmpMessage({
            source: sender.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gasLimit,
            nonce: 1,
            data: data
        });
        Batch memory batch = TestUtils.makeBatch(0, gmp);
        Signature memory sig = TestUtils.sign(admin, gateway, batch, nonce);

        console.log("messageSize", messageSize);
        console.log("gasLimit", gasLimit);

        // Execute the GMP message
        bytes32 gmpId = gmp.messageId();
        vm.expectEmit(true, true, true, true);
        emit Gateway.GmpExecuted(gmpId, gmp.source, gmp.dest, GmpStatus.SUCCESS, bytes32(uint256(gasLimit)));
        uint256 balanceBefore = sender.balance;
        gateway.execute{gas: 10_000_000}(sig, batch);
        VmSafe.Gas memory gas = vm.lastCallGas();
        assertEq(balanceBefore, sender.balance, "Balance should not change");
        assertEq(gas.gasLimit - gas.gasTotalUsed, gas.gasRemaining);

        uint256 mGasUsed = gas.gasTotalUsed;
        uint256 cGasUsed = GasUtils.estimateGas(uint16(gmp.data.length), 0, gmp.gasLimit);
        console.log("gasUsed", mGasUsed, cGasUsed);
        assertEq(cGasUsed, mGasUsed, "gasUsed mismatch");
    }
}
