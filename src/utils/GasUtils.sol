// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/GasUtils.sol)

pragma solidity ^0.8.20;

import {UFloat9x56, UFloatMath} from "./Float9x56.sol";
import {BranchlessMath} from "./BranchlessMath.sol";

/**
 * @dev Utilities for branchless operations, useful when a constant gas cost is required.
 */
library GasUtils {
    uint256 internal constant EXECUTION_BASE_COST = 39230 + 6700;

    using BranchlessMath for uint256;

    /**
     * @dev Compute the amount of gas used by the `GatewayProxy`.
     * @param calldataLen The length of the calldata
     * @param returnLen The length of the return data
     */
    function proxyOverheadGasCost(uint16 calldataLen, uint16 returnLen) internal pure returns (uint256) {
        unchecked {
            // Base cost: OPCODES + COLD READ STORAGE _implementation
            uint256 gasCost = 2257 + 2500;

            // CALLDATACOPY
            gasCost += ((uint256(calldataLen) + 31) >> 5) * 3;

            // RETURNDATACOPY
            gasCost += ((uint256(returnLen) + 31) >> 5) * 3;

            // MEMORY EXPANSION
            uint256 words = BranchlessMath.max(calldataLen, returnLen);
            words = (words + 31) >> 5;
            gasCost += ((words * words) >> 9) + (words * 3);
            return gasCost;
        }
    }

    /**
     * @dev Estimate the price in wei for send an GMP message.
     * @param gasPrice The gas price in UFloat9x56 format.
     * @param baseFee The base fee in wei.
     * @param nonZeros The number of non-zero bytes in the gmp data.
     * @param zeros The number of zero bytes in the gmp data.
     * @param gasLimit The message gas limit.
     */
    function estimateWeiCost(UFloat9x56 gasPrice, uint256 baseFee, uint16 nonZeros, uint16 zeros, uint256 gasLimit)
        internal
        pure
        returns (uint256)
    {
        unchecked {
            // Add execution cost
            uint256 gasCost = estimateGas(nonZeros, zeros, gasLimit);

            // Calculate the gas cost: gasPrice * gasCost + baseFee
            return UFloatMath.saturatingMul(gasPrice, gasCost).saturatingAdd(baseFee);
        }
    }

    /**
     * @dev Estimate the gas cost of a GMP message.
     * @param dataNonZeros The number of non-zero bytes in the gmp data.
     * @param dataZeros The number of zero bytes in the gmp data.
     * @param gasLimit The message gas limit.
     */
    function estimateGas(uint16 dataNonZeros, uint16 dataZeros, uint256 gasLimit) internal pure returns (uint256) {
        uint256 messageSize = uint256(dataNonZeros) + uint256(dataZeros);
        unchecked {
            // add execution cost
            uint256 gasCost = computeExecutionRefund(uint16(BranchlessMath.min(messageSize, type(uint16).max)));
            gasCost = gasCost.saturatingAdd(gasLimit);

            // add base cost
            gasCost = gasCost.saturatingAdd(21000);

            // calldata zero bytes
            uint256 zeros = 31 + 30 + 12 + 30 + 31 + 30;
            zeros = zeros.saturatingAdd((messageSize.saturatingAdd(31) & 0xffffe0) - uint256(dataZeros));
            gasCost = gasCost.saturatingAdd(zeros.saturatingMul(4));

            // calldata non-zero bytes
            uint256 nonZeros = uint256(dataNonZeros).saturatingAdd(4 + 96 + 1 + 32 + 2 + 20 + 2 + 32 + 32 + 1 + 2);
            gasCost = gasCost.saturatingAdd(nonZeros.saturatingMul(16));

            return gasCost;
        }
    }

    /**
     * @dev Compute the gas needed for the transaction, this is different from the gas used.
     * `gas needed > gas used` because of EIP-150
     */
    function executionGasNeeded(uint256 messageSize, uint256 gasLimit) internal pure returns (uint256 gasNeeded) {
        unchecked {
            gasNeeded = EXECUTION_BASE_COST + 2114;

            // Convert message size to calldata size
            uint256 calldataSize = ((messageSize + 31) & 0xffe0) + 388;

            // Base cost
            uint256 words = (calldataSize + 31) >> 5;
            gasNeeded += ((words - 1) / 15) * 1845;

            // CALLDATACOPY
            words = (messageSize + 31) >> 5;
            gasNeeded += words * 3;

            // keccak256 (6 gas per word)
            gasNeeded += words * 6;

            // Memory expansion cost
            words = 0xa4 + (words << 5); // onGmpReceived encoded call size
            words = (words + 31) & 0xffe0;
            words += 0x0200; // Memory size
            words = (words + 31) >> 5; // to words
            gasNeeded += ((words * words) >> 9) + (words * 3);

            // Add the gas limit
            gasNeeded += gasLimit.saturatingMul(64).saturatingDiv(63);

            // Add `all but one 64th`, as the defined by EIP-150
            gasNeeded = gasNeeded.saturatingMul(64).saturatingDiv(63);
            gasNeeded += 2600; // DELEGATECALL + COLD CONTRACT ADDRESS
            gasNeeded += 2121; // OPCODES + COLD SLOAD

            // CALLDATACOPY
            words = (calldataSize + 31) >> 5;
            gasNeeded += 3;
            gasNeeded += words * 3;

            // Memory Expansion
            gasNeeded += words * 3;
            gasNeeded += (words * words) >> 9;

            return gasNeeded;
        }
    }

    /**
     * @dev Compute the gas that should be refunded to the executor for the execution.
     */
    function computeExecutionRefund(uint16 messageSize) internal pure returns (uint256 executionCost) {
        // Add the base execution gas cost
        executionCost = EXECUTION_BASE_COST;

        // Safety: The operations below can't overflow because the message size can't be greater than 2^16
        unchecked {
            // Add padding to the message size, making it a multiple of 32
            uint256 messagePadded = (uint256(messageSize) + 31) & 0xffffe0;

            // Proxy Overhead
            uint256 words = messagePadded + 388; // selector + Signature + GmpMessage
            words = BranchlessMath.min(words, type(uint16).max);
            executionCost += proxyOverheadGasCost(uint16(words), 64);

            // Base Cost calculation
            words = (words + 31) >> 5;
            executionCost += ((words - 1) / 15) * 1845;

            // calldatacopy (3 gas per word)
            words = messagePadded >> 5;
            executionCost += words * 3;

            // keccak256 (6 gas per word)
            executionCost += words * 6;

            // Memory expansion cost
            words = 0xa4 + (words << 5); // onGmpReceived encoded call size
            words = (words + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0;
            words += 0x0200; // Memory size
            words = (words + 31) >> 5; // to words
            executionCost += ((words * words) >> 9) + (words * 3);
        }
    }

    /**
     * @dev Compute the transaction base cost.
     * OBS: This function must be used ONLY inside Gateway.execute method, because it also consider itself gas cost.
     */
    function executionGasCost(uint256 messageSize) internal pure returns (uint256 baseCost, uint256 executionCost) {
        // Calculate Gateway.execute dynamic cost
        executionCost = EXECUTION_BASE_COST;
        unchecked {
            uint256 words = (messageSize + 31) & 0xffe0;
            words += 388;
            executionCost += proxyOverheadGasCost(uint16(words), 64);

            // Base Cost calculation
            words = (words + 31) >> 5;
            executionCost += ((words - 1) / 15) * 1845;

            // calldatacopy (3 gas per word)
            words = (messageSize + 31) >> 5;
            executionCost += words * 3;

            // keccak256 (6 gas per word)
            executionCost += words * 6;

            // Memory expansion cost
            words = 0xa4 + (words << 5); // onGmpReceived encoded call size
            words = (words + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0;
            words += 0x0200; // Memory size
            words = (words + 31) >> 5; // to words
            executionCost += ((words * words) >> 9) + (words * 3);
        }

        // Efficient algorithm for counting non-zero calldata bytes in chunks of 480 bytes at time
        // computation gas cost = 1845 * ceil(msg.data.length / 480) + 61
        baseCost = calldataGasCost();
    }

    /**
     * @dev Count the number of non-zero bytes in a byte sequence.
     */
    function countNonZeros(bytes memory data) internal pure returns (uint256 nonZeros) {
        /// @solidity memory-safe-assembly
        assembly {
            // Efficient algorithm for counting non-zero bytes in parallel
            let size := mload(data)

            // Temporary set the length of the data to zero
            mstore(data, 0)

            nonZeros := 0
            for {
                // 32 byte aligned pointer, ex: if data.length is 54, then `ptr = data + 32`
                let ptr := add(data, and(add(size, 31), 0xffffffe0))
                let end := xor(data, mul(xor(sub(ptr, 480), data), gt(sub(ptr, data), 480)))
            } true { end := xor(data, mul(xor(sub(ptr, 480), data), gt(sub(ptr, data), 480))) } {
                // Normalize and count non-zero bytes in parallel
                let v := 0
                for {} gt(ptr, end) { ptr := sub(ptr, 32) } {
                    let r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, 0x0101010101010101010101010101010101010101010101010101010101010101)
                    v := add(v, r)
                }

                // Sum bytes in parallel
                v := add(v, shr(128, v))
                v := add(v, shr(64, v))
                v := add(v, shr(32, v))
                v := add(v, shr(16, v))
                v := and(v, 0xffff)
                v := add(and(v, 0xff), shr(8, v))
                nonZeros := add(nonZeros, v)

                if eq(ptr, data) { break }
            }

            // Restore the original length of the data
            mstore(data, size)
        }
    }

    /**
     * @dev Compute the transaction base cost.
     */
    function calldataGasCost() internal pure returns (uint256 baseCost) {
        // Efficient algorithm for counting non-zero calldata bytes in chunks of 480 bytes at time
        // computation gas cost = 1845 * ceil(msg.data.length / 480) + 61
        assembly {
            baseCost := 0
            for {
                let ptr := 0
                let mask := 0x0101010101010101010101010101010101010101010101010101010101010101
            } lt(ptr, calldatasize()) { ptr := add(ptr, 32) } {
                // 1
                let v := calldataload(ptr)
                v := or(v, shr(4, v))
                v := or(v, shr(2, v))
                v := or(v, shr(1, v))
                v := and(v, mask)
                {
                    // 2
                    ptr := add(ptr, 32)
                    let r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 3
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 4
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 5
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 6
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 7
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 8
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 9
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 10
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 11
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 12
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 13
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 14
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 15
                    ptr := add(ptr, 32)
                    r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                }

                // Count bytes in parallel
                v := add(v, shr(128, v))
                v := add(v, shr(64, v))
                v := add(v, shr(32, v))
                v := add(v, shr(16, v))
                v := and(v, 0xffff)
                v := add(and(v, 0xff), shr(8, v))
                baseCost := add(baseCost, v)
            }
            baseCost := add(21000, add(mul(sub(calldatasize(), baseCost), 4), mul(baseCost, 16)))
        }
    }
}
