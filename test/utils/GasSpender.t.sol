// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Gateway.t.sol)

pragma solidity >=0.8.0;

import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TestUtils} from "../TestUtils.sol";
import {GasSpender} from "./GasSpender.sol";
import {GasUtils} from "../../src/utils/GasUtils.sol";
import {IGmpReceiver} from "../../src/interfaces/IGmpReceiver.sol";

contract GasSpenderBase is Test {
    function buildCall(uint256 gasToWaste) private pure returns (uint256 gasLimit, bytes memory encodedCall) {
        // Encode the `IGmpReceiver.onGmpReceived` call
        encodedCall = abi.encodeCall(
            IGmpReceiver.onGmpReceived,
            (
                0x0000000000000000000000000000000000000000000000000000000000000000,
                1,
                0x0000000000000000000000000000000000000000000000000000000000000000,
                abi.encode(gasToWaste)
            )
        );
        gasLimit = TestUtils.calculateBaseCost(encodedCall) + gasToWaste;
    }

    function test_onGmpReceivedWorks(uint16 delta) external {
        // Guarantee the gas limit is not less than 1000
        uint256 gasToWaste = 1000 + uint256(delta);
        vm.txGasPrice(1);
        
        // Create the Sender account
        address sender = TestUtils.createTestAccount(100 ether);
        
        // Deploy the GasSpender contract
        GasSpender spender = new GasSpender();

        // Encode the `IGmpReceiver.onGmpReceived` call
        (uint256 gasLimit, bytes memory encodedCall) = buildCall(gasToWaste);

        (uint256 gasUsed,, bytes memory output) =
            TestUtils.executeCall(sender, address(spender), gasLimit, 0, encodedCall);
        assertEq(gasUsed, gasToWaste);
        assertEq(output.length, 32);
    }

    function test_revertsMoreGas(uint16 delta) external {
        // Guarantee the gas limit is not less than 1000
        uint256 gasToWaste = 1000 + uint256(delta);
        vm.txGasPrice(1);
        
        // Create the Sender account
        address sender = TestUtils.createTestAccount(100 ether);
        
        // Deploy the GasSpender contract
        GasSpender spender = new GasSpender();

        // Encode the `IGmpReceiver.onGmpReceived` call
        (uint256 gasLimit, bytes memory encodedCall) = buildCall(gasToWaste);

        vm.expectRevert();
        TestUtils.executeCall(sender, address(spender), gasLimit + 1, 0, encodedCall);
    }

    function test_revertsLessGas(uint16 delta) external {
        // Guarantee the gas limit is not less than 1000
        uint256 gasToWaste = 1000 + uint256(delta);
        vm.txGasPrice(1);
        
        // Create the Sender account
        address sender = TestUtils.createTestAccount(100 ether);
        
        // Deploy the GasSpender contract
        GasSpender spender = new GasSpender();

        // Encode the `IGmpReceiver.onGmpReceived` call
        (uint256 gasLimit, bytes memory encodedCall) = buildCall(gasToWaste);

        vm.expectRevert();
        TestUtils.executeCall(sender, address(spender), gasLimit - 1, 0, encodedCall);
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
contract GasSpenderTest is GasSpenderBase {
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
    bytes32 private constant INLINE_BYTECODE = 0x6000823f505a96949290959391f15a607b019091036800000000000000000052;

    constructor() payable {
        // In solidity the child's constructor are executed before the parent's constructor,
        // so once this contract extends `GatewayBase`, it's constructor is executed first.

        // Copy `GatewayBase` runtime code into memory.
        bytes memory runtimeCode = type(GasSpenderBase).runtimeCode;

        // Replaces the first occurence of `0x7E7E..` in the runtime code by the `INLINE_BYTECODE`
        assembly ("memory-safe") {
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
