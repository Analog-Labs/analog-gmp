// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/GasUtils.sol)

pragma solidity ^0.8.20;

import {UFloat9x56, UFloatMath} from "./Float9x56.sol";
import {BranchlessMath} from "./BranchlessMath.sol";

/**
 * @dev Utilities for branchless operations, useful when a constant gas cost is required.
 */
library GasUtils {
    // uint256 internal constant BASE_OVERHEAD_COST = 21000;
    // uint256 internal constant EXECUTION_BASE_COST = 43_204 + 4500 - 12908;
    uint256 internal constant EXECUTION_BASE_COST = 39605;

    using BranchlessMath for uint256;

    /**
     * @dev Compute the amount of gas used by the `GatewayProxy`.
     * @param calldataLen The length of the calldata
     * @param returnLen The length of the return data
     */
    function proxyOverheadGasCost(uint256 calldataLen, uint256 returnLen) internal pure returns (uint256) {
        unchecked {
            // Base cost: OPCODES + COLD READ STORAGE _implementation
            uint256 gasCost = 2257 + 2500;

            // CALLDATACOPY
            gasCost += ((calldataLen + 31) >> 5) * 3;

            // RETURN DATA SIZE
            gasCost += ((returnLen + 31) >> 5) * 3;

            // MEMORY EXPANSION
            uint256 words = BranchlessMath.max(calldataLen, returnLen);
            words = (words + 31) >> 5;
            gasCost += ((words * words) >> 9) + (words * 3);
            return gasCost;
        }
    }

    /**
     * @dev Estimate the gas cost of a GMP message.
     */
    function estimateGasCost(UFloat9x56 gasPrice, uint256 baseFee, uint256 messageSize, uint256 gasLimit)
        internal
        pure
        returns (uint256)
    {
        unchecked {
            // Calculate the gas needed for the transaction
            uint256 gap = (messageSize.saturatingAdd(31) >> 5) << 5;
            gap = gap.saturatingSub(messageSize);
            uint256 gasNeeded = proxyOverheadGasCost(messageSize.saturatingAdd(388).saturatingAdd(gap), 32);
            gasNeeded = gasNeeded.saturatingAdd(messageSize.saturatingAdd(177).saturatingMul(16));
            gasNeeded = gasNeeded.saturatingAdd(gap.saturatingAdd(211).saturatingMul(4));
            gasNeeded = gasNeeded.saturatingAdd(computeExecutionRefund(messageSize).saturatingAdd(gasLimit));

            // Calculate the gas cost: gasPrice * gasNeeded + baseFee
            return UFloatMath.saturatingMul(gasPrice, gasNeeded).saturatingAdd(baseFee);
        }
    }

    /**
     * @dev Compute the gas needed for the transaction, this is different from the gas used.
     * `gas needed > gas used` because of EIP-150
     */
    function executionGasNeeded(uint256 messageSize) internal pure returns (uint256 gasNeeded) {
        unchecked {
            gasNeeded = EXECUTION_BASE_COST;

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
    function computeExecutionRefund(uint256 messageSize) internal pure returns (uint256 executionCost) {
        executionCost = EXECUTION_BASE_COST;
        unchecked {
            uint256 words = (messageSize + 31) & 0xffe0;
            words += 388;
            executionCost += proxyOverheadGasCost(words, 64);

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
            executionCost += proxyOverheadGasCost(words, 64);

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

    /**
     * @dev Compute the transaction base cost.
     */
    function computeBaseCost(bytes memory data) internal pure returns (uint256 baseCost) {
        // Efficient algorithm for counting non-zero calldata bytes in chunks of 480 bytes at time
        // computation gas cost = 1845 * ceil(msg.data.length / 480) + 61
        assembly {
            baseCost := 0
            for {
                let ptr := add(data, 0x20)
                let end := add(ptr, mload(data))
                let mask := 0x0101010101010101010101010101010101010101010101010101010101010101
            } lt(ptr, end) { ptr := add(ptr, 32) } {
                // 1
                let v := mload(ptr)
                v := or(v, shr(4, v))
                v := or(v, shr(2, v))
                v := or(v, shr(1, v))
                v := and(v, mask)
                {
                    // 2
                    ptr := add(ptr, 32)
                    let r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 3
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 4
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 5
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 6
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 7
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 8
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 9
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 10
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 11
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 12
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 13
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 14
                    ptr := add(ptr, 32)
                    r := mload(ptr)
                    r := or(r, shr(4, r))
                    r := or(r, shr(2, r))
                    r := or(r, shr(1, r))
                    r := and(r, mask)
                    v := add(v, r)
                    // 15
                    ptr := add(ptr, 32)
                    r := mload(ptr)
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
            baseCost := add(21000, add(mul(sub(mload(data), baseCost), 4), mul(baseCost, 16)))
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
