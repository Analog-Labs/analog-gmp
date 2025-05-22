// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/TestUtils.sol)

pragma solidity >=0.8.0;

import {VmSafe, Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {Signer} from "../lib/frost-evm/sol/Signer.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
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

/**
 * @dev Utilities for testing purposes
 */
library TestUtils {
    using BranchlessMath for uint256;

    // Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
    address internal constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm internal constant vm = Vm(VM_ADDRESS);

    /**
     * @dev Count the number of non-zero bytes in a byte sequence.
     * Reference: https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
     */
    function countNonZeros(bytes memory data) internal pure returns (uint256 nonZeros) {
        assembly ("memory-safe") {
            // Efficient algorithm for counting non-zero bytes in parallel
            nonZeros := 0
            for {
                // 32 byte aligned pointer, ex: if data.length is 54, `ptr` starts at 32
                let ptr := add(data, and(add(mload(data), 31), 0xffffffe0))
            } gt(ptr, data) { ptr := sub(ptr, 32) } {
                // Normalize
                let v := mload(ptr)
                v := or(v, shr(4, v))
                v := or(v, shr(2, v))
                v := or(v, shr(1, v))
                v := and(v, 0x0101010101010101010101010101010101010101010101010101010101010101)

                // Count bytes in parallel
                v := add(v, shr(128, v))
                v := add(v, shr(64, v))
                v := add(v, shr(32, v))
                v := add(v, shr(16, v))
                v := add(v, shr(8, v))
                v := and(v, 0xff)
                nonZeros := add(nonZeros, v)
            }
        }
    }

    /**
     * @dev Calculate the tx base cost.
     * formula: 21000 + zeros * 4 + nonZeros * 16
     * Reference: https://eips.ethereum.org/EIPS/eip-2028
     */
    function calculateBaseCost(bytes memory txData) internal pure returns (uint256 baseCost) {
        uint256 nonZeros = countNonZeros(txData);
        uint256 zeros = txData.length - nonZeros;
        baseCost = 21_000 + (nonZeros * 16) + (zeros * 4);
    }

    // Workaround for set the tx.gasLimit, currently is not possible to define the gaslimit in foundry
    // Reference: https://github.com/foundry-rs/foundry/issues/2224
    function _call(address addr, uint256 gasLimit, uint256 value, bytes memory data)
        private
        returns (uint256 gasUsed, bool success, bytes memory out)
    {
        require(gasleft() > gasLimit.saturatingAdd(5000), "insufficient gas");
        require(addr.code.length > 0, "Not a contract address");
        assembly ("memory-safe") {
            success :=
                call(
                    0x7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E, // Code Injection TAG
                    gasLimit, // gas limit
                    addr, // addr
                    value, // value
                    add(data, 32), // arg offset
                    mload(data), // arg size
                    0 // return offset
                )
            gasUsed := mload(0)

            out := mload(0x40)
            let size := returndatasize()
            mstore(out, size)
            let ptr := add(out, 32)
            returndatacopy(ptr, 0, size)
            mstore(0x40, add(ptr, size))
        }
    }

    // Execute a contract call and calculate the acurrate execution gas cost
    function executeCall(address sender, address dest, uint256 gasLimit, uint256 value, bytes memory data)
        internal
        returns (uint256 executionCost, uint256 baseCost, bytes memory out)
    {
        bool success;
        (executionCost, baseCost, success, out) = tryExecuteCall(sender, dest, gasLimit, value, data);
        // Revert if the execution failed
        assembly {
            if iszero(success) { revert(add(out, 32), mload(out)) }
        }
    }

    // Execute a contract call and calculate the acurrate execution gas cost
    function tryExecuteCall(address sender, address dest, uint256 gasLimit, uint256 value, bytes memory data)
        internal
        returns (uint256 executionCost, uint256 baseCost, bool success, bytes memory out)
    {
        // Guarantee there's enough gas to execute the call
        {
            uint256 gasRequired = (gasLimit * 64) / 63;
            gasRequired += 50_000;
            require(gasleft() > gasRequired, "insufficient gas left to execute call");
        }

        // Compute the base tx cost (21k + 4 * zeros + 16 * nonZeros)
        baseCost = calculateBaseCost(data);

        // Decrement sender base cost and value
        {
            uint256 txFees = gasLimit.saturatingMul(tx.gasprice);
            require(sender.balance >= txFees.saturatingAdd(value), "account has no sufficient funds");
            vm.deal(sender, sender.balance - txFees);
            gasLimit = gasLimit.saturatingSub(baseCost);
        }

        // Execute
        {
            (VmSafe.CallerMode callerMode, address msgSender, address txOrigin) =
                setCallerMode(VmSafe.CallerMode.RecurrentPrank, sender, sender);
            (executionCost, success, out) = _call(dest, gasLimit, value, data);
            setCallerMode(callerMode, msgSender, txOrigin);
        }

        // Refund unused gas
        uint256 refund = gasLimit.saturatingSub(executionCost).saturatingMul(tx.gasprice);
        if (refund > 0) {
            vm.deal(sender, sender.balance + refund);
        }
    }

    function setCallerMode(VmSafe.CallerMode callerMode, address msgSender, address txOrigin)
        internal
        returns (VmSafe.CallerMode prevCallerMode, address prevMsgSender, address prevTxOrigin)
    {
        (prevCallerMode, prevMsgSender, prevTxOrigin) = vm.readCallers();

        // Stop previous caller mode
        if (prevCallerMode == VmSafe.CallerMode.RecurrentBroadcast) {
            vm.stopBroadcast();
        } else if (prevCallerMode == VmSafe.CallerMode.RecurrentPrank) {
            vm.stopPrank();
        }

        // Set new caller mode
        if (callerMode == VmSafe.CallerMode.Broadcast) {
            vm.broadcast(msgSender);
        } else if (callerMode == VmSafe.CallerMode.RecurrentBroadcast) {
            vm.startBroadcast(msgSender);
        } else if (callerMode == VmSafe.CallerMode.Prank) {
            vm.prank(msgSender, txOrigin);
        } else if (callerMode == VmSafe.CallerMode.RecurrentPrank) {
            vm.startPrank(msgSender, txOrigin);
        }
    }

    function prank(address msgSender, address txOrigin, function() f) internal {
        VmSafe.CallerMode callerMode = VmSafe.CallerMode.RecurrentPrank;
        (callerMode, msgSender, txOrigin) = setCallerMode(VmSafe.CallerMode.RecurrentPrank, msgSender, txOrigin);
        f();
        setCallerMode(callerMode, msgSender, txOrigin);
    }

    function prank(address msgSender, function() f) internal {
        VmSafe.CallerMode callerMode = VmSafe.CallerMode.RecurrentPrank;
        address txOrigin = msgSender;
        (callerMode, msgSender, txOrigin) = setCallerMode(VmSafe.CallerMode.RecurrentPrank, msgSender, txOrigin);
        f();
        setCallerMode(callerMode, msgSender, txOrigin);
    }

    /**
     * @dev Deploy a new Gateway and GatewayProxy contracts.
     */
    function setupGateway(
        VmSafe.Wallet memory admin,
        uint16 network
    ) internal returns (IGateway gw) {
        vm.startPrank(admin.addr, admin.addr);
        GatewayProxy proxy = new GatewayProxy(admin.addr);
        Gateway gateway = new Gateway(network, address(proxy));
        proxy.upgrade(address(gateway));
        vm.deal(address(proxy), 10 ether);
        vm.stopPrank();
        return IGateway(address(proxy));
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
        gw.setRoute(Route({
            networkId: NetworkID.wrap(network),
            gasLimit: 1_000_000,
            baseFee: 0,
            gateway: bytes32(uint(1)),
            relativeGasPriceNumerator: 1,
            relativeGasPriceDenominator: 1
        }));
        vm.stopPrank();
    }
}
