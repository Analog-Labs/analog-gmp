// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/GasUtils.sol)

pragma solidity ^0.8.20;

import {UFloat9x56, UFloatMath} from "./Float9x56.sol";
import {BranchlessMath} from "./BranchlessMath.sol";

/**
 * @dev Utilities for compute the GMP gas price, gas cost and gas needed.
 */
library GasUtils {
    /**
     * @dev Base cost of the `IExecutor.execute` method.
     */
    uint256 internal constant EXECUTION_BASE_COST = 37647 + 6800;

    /**
     * @dev Base cost of the `IGateway.submitMessage` method.
     */
    uint256 internal constant SUBMIT_BASE_COST = 9640 + 6800 + 6500;

    using BranchlessMath for uint256;

    /**
     * @dev Compute the amount of gas used by the `GatewayProxy`.
     * @param calldataLen The length of the calldata in bytes
     * @param returnLen The length of the return data in bytes
     */
    function proxyOverheadGasCost(uint256 calldataLen, uint256 returnLen) internal pure returns (uint256) {
        unchecked {
            // Convert the calldata and return data length to words
            calldataLen = calldataLen.saturatingAdd(31) >> 5;
            returnLen = returnLen.saturatingAdd(31) >> 5;

            // Base cost: OPCODES + COLD READ STORAGE _implementation
            uint256 gasCost = 2257 + 2500;

            // CALLDATACOPY
            gasCost = gasCost.saturatingAdd(calldataLen * 3);

            // RETURNDATACOPY
            gasCost = gasCost.saturatingAdd(returnLen * 3);

            // MEMORY EXPANSION
            uint256 words = BranchlessMath.max(calldataLen, returnLen);
            gasCost = gasCost.saturatingAdd((words.saturatingMul(words) >> 9).saturatingAdd(words * 3));
            return gasCost;
        }
    }

    /**
     * @dev Compute the gas cost of the `IGateway.submitMessage` method.
     * @param messageSize The size of the message in bytes.
     */
    function submitMessageGasCost(uint16 messageSize) internal pure returns (uint256 gasCost) {
        unchecked {
            gasCost = SUBMIT_BASE_COST;

            // Convert message size to calldata size
            uint256 calldataSize = ((messageSize + 31) & 0xffe0) + 164;

            // Proxy overhead
            gasCost += proxyOverheadGasCost(uint16(calldataSize), 32);

            // `countNonZeros` gas cost
            uint256 words = (messageSize + 31) >> 5;
            gasCost += (words * 106) + (((words + 254) / 255) * 214);

            // CALLDATACOPY
            gasCost += words * 3;

            // keccak256 (6 gas per word)
            gasCost += words * 6;

            // emit GmpCreated() gas cost (8 gas per byte)
            gasCost += words << 8;

            // Memory expansion cost
            words += 13;
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
        // Add execution cost
        uint256 gasCost = estimateGas(nonZeros, zeros, gasLimit);

        // Calculate the gas cost: gasPrice * gasCost + baseFee
        return UFloatMath.saturatingMul(gasPrice, gasCost).saturatingAdd(baseFee);
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
            uint256 gasCost =
                computeExecutionRefund(uint16(BranchlessMath.min(messageSize, type(uint16).max)), gasLimit);
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
            gasNeeded += (words * 106) + (((words + 254) / 255) * 214);

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
     * @param messageSize The size of the message.
     * @param gasUsed The gas used by the gmp message.
     */
    function computeExecutionRefund(uint16 messageSize, uint256 gasUsed)
        internal
        pure
        returns (uint256 executionCost)
    {
        // Add the base execution gas cost
        executionCost = EXECUTION_BASE_COST.saturatingAdd(gasUsed);

        // Safety: The operations below can't overflow because the message size can't be greater than 2^16
        unchecked {
            // Add padding to the message size, making it a multiple of 32
            uint256 messagePadded = (uint256(messageSize) + 31) & 0xffffe0;

            // Proxy Overhead
            uint256 words = messagePadded + 388; // selector + Signature + GmpMessage
            executionCost = executionCost.saturatingAdd(proxyOverheadGasCost(words, 64));

            // Base Cost calculation
            words = (words + 31) >> 5;
            executionCost = executionCost.saturatingAdd((words * 106) + (((words + 254) / 255) * 214));

            // calldatacopy (3 gas per word)
            words = messagePadded >> 5;
            executionCost = executionCost.saturatingAdd(words * 3);

            // keccak256 (6 gas per word)
            executionCost = executionCost.saturatingAdd(words * 6);

            // Memory expansion cost
            words = 0xa4 + (words << 5); // onGmpReceived encoded call size
            words = (words + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0;
            words += 0x0200; // Memory size
            words = (words + 31) >> 5; // to words
            executionCost = executionCost.saturatingAdd(((words * words) >> 9) + (words * 3));
        }
    }

    /**
     * @dev Count the number of non-zero bytes in a byte sequence.
     * gas cost = 217 + (words * 112) + ((words - 1) * 193)
     */
    function countNonZeros(bytes memory data) internal pure returns (uint256 nonZeros) {
        // /// @solidity memory-safe-assembly
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
     * @dev Count the number of non-zero bytes from calldata.
     * gas cost = 224 + (words * 106) + (((words - 1) / 255) * 214)
     */
    function countNonZerosCalldata(bytes calldata data) internal pure returns (uint256 nonZeros) {
        /// @solidity memory-safe-assembly
        assembly {
            nonZeros := 0
            for {
                let ptr := data.offset
                let end := add(ptr, data.length)
            } lt(ptr, end) {} {
                // calculate min(ptr + data.length, ptr + 8160)
                let range := add(ptr, 8160)
                range := xor(end, mul(xor(range, end), lt(range, end)))

                // Normalize and count non-zero bytes in parallel
                let v := 0
                for {} lt(ptr, range) { ptr := add(ptr, 32) } {
                    let r := calldataload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, 0x0101010101010101010101010101010101010101010101010101010101010101)
                    v := add(v, r)
                }

                // Sum bytes in parallel
                {
                    let l := and(v, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                    v := shr(8, xor(v, l))
                    v := add(v, l)
                }
                v := add(v, shr(128, v))
                v := add(v, shr(64, v))
                v := add(v, shr(32, v))
                v := add(v, shr(16, v))
                v := and(v, 0xffff)
                nonZeros := add(nonZeros, v)
            }
        }
    }

    /**
     * @dev Compute the transaction base cost.
     */
    function calldataBaseCost() internal pure returns (uint256) {
        unchecked {
            uint256 nonZeros = countNonZerosCalldata(msg.data);
            uint256 zeros = msg.data.length - nonZeros;
            return 21000 + (nonZeros * 16) + (zeros * 4);
        }
    }
}
