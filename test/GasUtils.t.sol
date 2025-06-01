// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/GasUtils.t.sol)

pragma solidity >=0.8.0;

import {Signer} from "frost-evm/sol/Signer.sol";
import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Gas, TestUtils} from "./TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {Gateway} from "../src/Gateway.sol";
import {GasUtils} from "../src/GasUtils.sol";
import {IGmpReceiver} from "gmp/src/IGmpReceiver.sol";
import {
    Command,
    GatewayOp,
    GmpMessage,
    Signature,
    TssKey,
    GmpStatus,
    PrimitiveUtils,
    Batch,
    GMP_VERSION,
    MAX_PAYLOAD_SIZE
} from "../src/Primitives.sol";

uint256 constant secret = 0x42;
uint256 constant nonce = 0x69;

contract MeasureGas {
    function baseGas(Signature calldata, Batch calldata) external pure returns (uint256) {
        return GasUtils.txBaseGas();
    }

    function proxyOverheadGas(Signature calldata, Batch calldata) external pure returns (uint256) {
        return GasUtils.proxyOverheadGas(msg.data.length);
    }
}

contract GasUtilsTest is Test {
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for address;
    using PrimitiveUtils for uint256;

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

    function test_calldata_size(uint16 messageSize) external {
        bytes memory data = new bytes(messageSize);
        GmpMessage memory gmp = GmpMessage({
            source: admin.addr.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 42,
            nonce: 42,
            data: data
        });
        Batch memory batch = TestUtils.makeBatch(1, gmp);
        Signature memory sig = TestUtils.sign(admin, gateway, batch, nonce);
        bytes memory call = abi.encodeCall(gateway.execute, (sig, batch));
        assertEq(call.length, GasUtils.calldataSize(messageSize));
    }

    /**
     * @dev Compare the estimated gas cost VS the actual gas cost of the `execute` method.
     */
    function test_reimbursment(uint16 messageSize, uint16 gasLimit) external {
        vm.txGasPrice(1);
        vm.assume(gasLimit >= 5000);
        vm.assume(messageSize <= (0x6000 - 32));
        messageSize += 32;
        VmSafe.Wallet memory sender = vm.createWallet(0xdead_beef);
        vm.deal(sender.addr, 10 ether);

        bytes memory data = new bytes(messageSize);
        assembly {
            mstore(add(data, 32), gasLimit)
        }
        GmpMessage memory gmp = GmpMessage({
            source: sender.addr.toSender(),
            srcNetwork: SRC_NETWORK_ID,
            dest: address(receiver),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: gasLimit,
            nonce: gasLimit,
            data: data
        });
        GatewayOp[] memory ops = new GatewayOp[](1);
        ops[0] = GatewayOp({command: Command.GMP, params: abi.encode(gmp)});
        Batch memory batch = Batch({version: GMP_VERSION, batchId: 0, numSigningSessions: 2, ops: ops});
        Signature memory sig = TestUtils.sign(admin, gateway, batch, nonce);

        console.log("messageSize", messageSize);
        console.log("gasLimit", gasLimit);

        MeasureGas m = new MeasureGas();
        uint256 baseGas = m.baseGas(sig, batch);
        console.log("baseGas", baseGas);

        // execute
        uint256 balanceBefore = admin.addr.balance;
        vm.startPrank(admin.addr);
        gateway.execute(sig, batch);
        VmSafe.Gas memory gas = vm.lastCallGas();
        vm.stopPrank();
        uint256 balanceAfter = admin.addr.balance;

        // check message executed
        assertEq(uint256(gateway.messages(gmp.messageId())), uint256(GmpStatus.SUCCESS));
        // check reimbursment
        assertEq(balanceAfter - balanceBefore - baseGas - gas.gasTotalUsed, 0, "Balance should not change");

        // execute second signing session
        balanceBefore = admin.addr.balance;
        vm.startPrank(admin.addr);
        gateway.execute(sig, batch);
        gas = vm.lastCallGas();
        vm.stopPrank();
        balanceAfter = admin.addr.balance;

        // check reimbursment
        assertEq(balanceAfter - balanceBefore - baseGas - gas.gasTotalUsed, 0, "Balance should not change");

        // check replay reverts
        vm.expectRevert("batch already executed");
        gateway.execute(sig, batch);
    }

    string path = "gas.csv";

    function test_measure_gas(uint16 messageSize) external {
        vm.assume(messageSize <= MAX_PAYLOAD_SIZE - 32);
        messageSize += 32;
        Gas memory gas = TestUtils.measureGas(messageSize);

        if (!vm.exists(path)) {
            vm.writeFile(path, "messageSize, executeGas, reimbursmentGas, baseGas\n");
        }
        string memory line = string.concat(
            Strings.toString(messageSize),
            ", ",
            Strings.toString(gas.executeGas),
            ", ",
            Strings.toString(gas.reimbursmentGas),
            ", ",
            Strings.toString(gas.baseGas)
        );
        vm.writeLine(path, line);
    }
}
