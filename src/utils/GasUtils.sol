// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/GasUtils.sol)

pragma solidity ^0.8.20;

/**
 * @dev Utilities for branchless operations, useful when a constant gas cost is required.
 */
library GasUtils {
    uint256 internal constant EXECUTION_BASE_COST = 43_303 + 4500;

    /**
     * @dev Compute the transaction base cost.
     */
    function executionGasCost(uint256 messageSize) internal pure returns (uint256 baseCost, uint256 executionCost) {
        // Calculate Gateway.execute dynamic cost
        executionCost = EXECUTION_BASE_COST;
        unchecked {
            // calldatacopy (3 gas per word)
            uint256 words = (messageSize + 31) >> 5;
            executionCost += words * 3;

            // keccak256 (6 gas per word)
            executionCost += words * 6;

            // Memory expansion cost
            words = 0xa4 + (words << 5); // onGmpReceived encoded call size
            words = (words + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0;
            words += 0x0200; // Memory size
            words = (words + 31) >> 5; // to words
            executionCost += ((words * words) / 512) + (words * 3);

            // Calculate Proxy memory expansion cost
            // Proxy execute(selector + signature + gmpData)
            words = 388 + ((messageSize + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
            words = (words + 31) >> 5;
            executionCost += ((words * words) / 512) + (words * 6);

            // Base Cost calculation
            executionCost += ((words - 1) / 15) * 1845;
        }

        // Efficient algorithm for counting non-zero calldata bytes in chunks of 480 bytes at time
        // computation gas cost = 1845 * ceil(msg.data.length / 480) + 61
        assembly {
            {
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
}
