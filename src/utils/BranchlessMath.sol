// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/BranchlessMath.sol)

pragma solidity >=0.8.20;

/**
 * @dev Utilities for branchless operations, useful when a constant gas cost is required.
 */
library BranchlessMath {
    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 x, uint256 y) internal pure returns (uint256) {
        return ternary(x < y, x, y);
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 x, uint256 y) internal pure returns (uint256) {
        return ternary(x > y, x, y);
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256 r) {
        // branchless select, works because:
        // b ^ (a ^ b) == a
        // b ^ 0 == b
        //
        // This is better than doing `condition ? a : b` because:
        // - Consumes less gas
        // - Constant gas cost regardless the inputs
        // - Reduces the final bytecode size
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternaryU64(bool condition, uint64 a, uint64 b) internal pure returns (uint64 r) {
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }

    /**
     * @dev Aligns `x` to 32 bytes.
     */
    function align32(uint256 x) internal pure returns (uint256 r) {
        unchecked {
            r = (x + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0;
        }
    }

    /**
     * @dev Convert byte count to 256bit word count, rounded up.
     */
    function toWordCount(uint256 byteCount) internal pure returns (uint256 words) {
        assembly {
            words := add(shr(5, byteCount), gt(and(byteCount, 0x1f), 0))
        }
    }
}
