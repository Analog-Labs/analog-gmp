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
     * @dev Unsigned saturating addition, bounds to UINT256 MAX instead of overflowing.
     * equivalent to:
     * uint256 r = x + y;
     * return r >= x ? r : UINT256_MAX;
     */
    function saturatingAdd(uint256 x, uint256 y) internal pure returns (uint256) {
        unchecked {
            x = x + y;
            y = 0 - toUint(x < y);
            return x | y;
        }
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     * equivalent to: x > y ? x - y : 0
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // equivalent to: a > b ? a - b : 0
            return (a - b) * toUint(a > b);
        }
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2 ** 256 - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a * b;
            bool success;
            assembly {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            return c | (toUint(success) - 1);
        }
    }

    /**
     * @dev Unsigned saturating division, bounds to UINT256 MAX instead of overflowing.
     */
    function saturatingDiv(uint256 x, uint256 y) internal pure returns (uint256 r) {
        assembly {
            // Solidity reverts with a division by zero error, while using inline assembly division does
            // not revert, it returns zero.
            // Reference: https://github.com/ethereum/solidity/issues/15200
            r := div(x, y)
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
            r = saturatingAdd(x, 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0;
        }
    }
}
