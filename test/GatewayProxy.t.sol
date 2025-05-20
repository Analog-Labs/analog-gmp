// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Gateway.t.sol)

pragma solidity >=0.8.0;

import {IUniversalFactory} from "../lib/universal-factory/src/IUniversalFactory.sol";
import {FactoryUtils} from "../lib/universal-factory/src/FactoryUtils.sol";
import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils, SigningKey, SigningUtils} from "./TestUtils.sol";
import {GasSpender} from "./utils/GasSpender.sol";
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

contract GatewayProxyTest is Test {
    using PrimitiveUtils for UpdateKeysMessage;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpSender;
    using PrimitiveUtils for address;
    using BranchlessMath for uint256;
    using SigningUtils for SigningKey;
    using FactoryUtils for IUniversalFactory;

    IGmpReceiver internal receiver;

    constructor() {
        receiver = IGmpReceiver(new GasSpender());
    }

    function test_deployGateway() external {
        VmSafe.Wallet memory admin = vm.createWallet(vm.randomUint());
        TestUtils.setupGateway(admin, 42);
    }
}
