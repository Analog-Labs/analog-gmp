// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Gateway.t.sol)

pragma solidity >=0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "./TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";

contract GatewayProxyTest is Test {
    IGmpReceiver internal receiver;

    constructor() {
        receiver = IGmpReceiver(new GasSpender());
    }

    function test_deployGateway() external {
        VmSafe.Wallet memory admin = vm.createWallet(vm.randomUint());
        TestUtils.setupGateway(admin, 42);
    }
}
