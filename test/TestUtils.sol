// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/TestUtils.sol)

pragma solidity >=0.8.0;

import {VmSafe, Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {Gateway} from "../src/Gateway.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {
    GmpMessage,
    UpdateKeysMessage,
    Signature,
    TssKey,
    Network,
    NetworkID,
    Route,
    GmpStatus,
    PrimitiveUtils,
    GmpSender
} from "../src/Primitives.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

    function setMockShard(VmSafe.Wallet memory admin, address gateway, VmSafe.Wallet memory shard) internal {
        Signer signer = new Signer(shard.privateKey);
        TssKey memory key = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        Gateway gw = Gateway(payable(gateway));
        vm.startPrank(admin.addr, admin.addr);
        gw.setShard(key);
        vm.stopPrank();
    }

    function setMockRoute(VmSafe.Wallet memory admin, address gateway, uint16 network) internal {
        Gateway gw = Gateway(payable(gateway));
        vm.startPrank(admin.addr, admin.addr);
        gw.setRoute(
            Route({
                networkId: NetworkID.wrap(network),
                gasLimit: 1_000_000,
                baseFee: 0,
                gateway: bytes32(uint256(1)),
                relativeGasPriceNumerator: 1,
                relativeGasPriceDenominator: 1
            })
        );
        vm.stopPrank();
    }

    function sign(VmSafe.Wallet memory shard, GmpMessage memory gmp, uint256 nonce)
        internal
        returns (Signature memory sig)
    {
        bytes32 hash = gmp.opHash();
        Signer signer = new Signer(shard.privateKey);
        (uint256 e, uint256 s) = signer.signPrehashed(uint256(hash), nonce);
        return Signature({xCoord: signer.xCoord(), e: e, s: s});
    }
}
