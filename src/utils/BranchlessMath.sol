// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/BranchlessMath.sol)

pragma solidity >=0.8.20;

/**
 * Rounding mode used when divide an integer.
 */
enum Rounding {
    // Rounds towards zero
    Floor,
    // Rounds to the nearest value; if the number falls midway,
    // it is rounded to the value above.
    Nearest,
    // Rounds towards positive infinite
    Ceil
}

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
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless select, works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            //
            // This is better than doing `condition ? a : b` because:
            // - Consumes less gas
            // - Constant gas cost regardless the inputs
            // - Reduces the final bytecode size
            return b ^ ((a ^ b) * toUint(condition));
        }
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternary(bool condition, int256 a, int256 b) internal pure returns (int256 r) {
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternary(bool condition, address a, address b) internal pure returns (address r) {
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternary(bool condition, bytes32 a, bytes32 b) internal pure returns (bytes32 r) {
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternaryU128(bool condition, uint128 a, uint128 b) internal pure returns (uint128 r) {
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
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternaryU32(bool condition, uint32 a, uint32 b) internal pure returns (uint32 r) {
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev If `condition` is true returns `a`, otherwise returns `b`.
     * see `BranchlessMath.ternary`
     */
    function ternaryU8(bool condition, uint8 a, uint8 b) internal pure returns (uint8 r) {
        assembly {
            r := xor(b, mul(xor(a, b), condition))
        }
    }

    /**
     * @dev If `condition` is true return `value`, otherwise return zero.
     * see `BranchlessMath.ternary`
     */
    function selectIf(bool condition, uint256 value) internal pure returns (uint256) {
        unchecked {
            return value * toUint(condition);
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
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // The following calculation ensures accurate ceiling division without overflow.
            // Since a is non-zero, (a - 1) / b will not overflow.
            // The largest possible result occurs when (a - 1) / b is type(uint256).max,
            // but the largest value we can obtain is type(uint256).max - 1, which happens
            // when a = type(uint256).max and b = 1.
            return selectIf(a > 0, ((a - 1) / b + 1));
        }
    }

    /**
     * @dev Unsigned saturating left shift, bounds to `2 ** 256 - 1` instead of overflowing.
     */
    function saturatingShl(uint256 x, uint8 shift) internal pure returns (uint256 r) {
        assembly {
            // Detect overflow by checking if (x >> (256 - shift)) > 0
            r := gt(shr(sub(256, shift), x), 0)

            // Bounds to `type(uint256).max` if an overflow happened
            r := or(shl(shift, x), sub(0, r))
        }
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     *
     * Ref: https://graphics.stanford.edu/~seander/bithacks.html#IntegerAbs
     */
    function abs(int256 a) internal pure returns (uint256 r) {
        assembly {
            // Formula from the "Bit Twiddling Hacks" by Sean Eron Anderson.
            // Since `n` is a signed integer, the generated bytecode will use the SAR opcode to perform the right shift,
            // taking advantage of the most significant (or "sign" bit) in two's complement representation.
            // This opcode adds new most significant bits set to the value of the previous most significant bit. As a result,
            // the mask will either be `bytes(0)` (if n is positive) or `~bytes32(0)` (if n is negative).
            let mask := sar(255, a)

            // A `bytes(0)` mask leaves the input unchanged, while a `~bytes32(0)` mask complements it.
            r := xor(add(a, mask), mask)
        }
    }

    /**
     * @dev Computes the absolute difference between x and y.
     */
    function absDiff(uint256 x, uint256 y) internal pure returns (uint256) {
        return abs(int256(x) - int256(y));
    }

    /**
     * @dev Computes the absolute difference between x and y.
     */
    function absDiff(int256 x, int256 y) internal pure returns (uint256) {
        return abs(x - y);
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
     * @dev Cast a boolean (false or true) to a int256 (0 or 1) with no jump.
     */
    function toInt(bool b) internal pure returns (int256 i) {
        assembly ("memory-safe") {
            i := iszero(iszero(b))
        }
    }

    /**
     * @dev Cast an address to uint256
     */
    function toUint(address addr) internal pure returns (uint256) {
        return uint256(uint160(addr));
    }

    /**
     * @dev Count the consecutive zero bits (trailing) on the right.
     */
    function trailingZeros(uint256 x) internal pure returns (uint256 r) {
        assembly {
            // Compute largest power of two divisor of `x`.
            x := and(x, sub(0, x))

            // Use De Bruijn lookups to convert the power of 2 to log2(x).
            // Reference: https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
            r := byte(and(div(80, mod(x, 255)), 31), 0x0706050000040000010003000000000000000000020000000000000000000000)
            r := add(byte(31, div(0xf8f0e8e0d8d0c8c0b8b0a8a09890888078706860585048403830282018100800, shr(r, x))), r)
        }
    }

    /**
     * @dev Count the consecutive zero bits (trailing) on the right.
     */
    function leadingZeros(uint256 x) internal pure returns (uint256 r) {
        return 255 - log2(x) + toUint(x == 0);
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        unchecked {
            // Round down to the closest power of 2
            // Reference: https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
            x |= x >> 1;
            x |= x >> 2;
            x |= x >> 4;
            x |= x >> 8;
            x |= x >> 16;
            x |= x >> 32;
            x |= x >> 64;
            x |= x >> 128;
            x = (x >> 1) + 1;

            // Use De Bruijn lookups to convert the power of 2 to floor(log2(x)).
            // Reference: https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
            assembly {
                r :=
                    byte(and(div(80, mod(x, 255)), 31), 0x0706050000040000010003000000000000000000020000000000000000000000)
                r :=
                    add(byte(31, div(0xf8f0e8e0d8d0c8c0b8b0a8a09890888078706860585048403830282018100800, shr(r, x))), r)
            }
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

    /**
     * @dev Computes `x * 2**exponent`, essentially shifting the value to the left when
     * `exp` is positive, or shift to the right when `exp` is negative.
     */
    function mul2pow(uint256 x, int256 exponent) internal pure returns (uint256) {
        unchecked {
            // Rationale:
            // - When the exponent is negative, then `x << exp` is zero.
            // - When the exponent is positive, then `x >> -exp` is zero.
            // Then we can use the `or` operation to get the correct result.
            // result = (x << exp) | (x >> -exp)
            return (x << uint256(exponent)) | (x >> uint256(-exponent));
        }
    }

    /**
     * @dev Computes `x * 2**exponent`, bounds to `2 ** 256 - 1` instead overflowing.
     */
    function saturatingMul2pow(uint256 x, int256 exponent) internal pure returns (uint256 result) {
        unchecked {
            result = mul2pow(x, exponent);
            // An overflow happens when exponent is positive and (x << exp) >> exp != x.
            bool success = (result >> uint256(exponent)) == (x * toUint(exponent > 0));
            // Bounds to `type(uint256).max` if `success` is false.
            return result | (toUint(success) - 1);
        }
    }
}
