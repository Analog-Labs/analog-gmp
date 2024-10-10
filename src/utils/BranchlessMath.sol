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
        /// @solidity memory-safe-assembly
        assembly {
            u := iszero(iszero(b))
        }
    }

    /**
     * @dev Cast a boolean (false or true) to a int256 (0 or 1) with no jump.
     */
    function toInt(bool b) internal pure returns (int256 i) {
        /// @solidity memory-safe-assembly
        assembly {
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
     * @dev Change the number endianess.
     */
    function swapEndianess(uint256 x) internal pure returns (uint256) {
        unchecked {
            // Swap Endianess
            uint256 mask;
            mask = 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF;
            x = ((x >> 8) & mask) | ((x << 8) & (mask << 8));
            mask = 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF;
            x = ((x >> 16) & mask) | ((x << 16) & (mask << 16));
            mask = 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF;
            x = ((x >> 32) & mask) | ((x << 32) & (mask << 32));
            mask = 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF;
            x = ((x >> 64) & mask) | ((x << 64) & (mask << 64));
            x = x >> 128 | x << 128;
            return x;
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256) {
        // Efficient branchless algorithm for compute floor(log2(x)), the algorithm works as follow:
        //
        // 1. First round down `x` to the closest power of 2 using an modified version of the Seander's `Round up
        //    to the next power of 2` algorithm, the version used here is modified to round down instead of up.
        //    ref: https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
        //
        // 2. Compute `n = x mod 255`, the `n` is used to split the equation in two parts that can be more efficiently
        //    computed using the `Logarithm's Product Rule`:
        //      - lemma: log2(x) == log2(x / n) + log2(n)
        //    this `n` guarantees that `x / n` is a power of two multiple of 256, we use this fact to build a lookup table
        //    that calculates `log2(x / n)` and `log2(n)` very efficiently.
        //
        // 3. Compute `prod0 = log2(n)`, given `x % 255` is a power of two, there are only 8 possible values for `n`, so
        //    `log2(n)` can be easily computed using a lookup table, here we use the opcode `BYTE` to lookup a 32-byte word.
        //
        // 4. Compute `prod1 = log2(x / n)`, we use the fact that `x / n` is a power of two multiple of 256, so there's exactly
        //    32 possible distinct values for `prod1`, respectively: 0, 8, 16, .. 240, 248. This allow an efficient lookup
        //    table to be created using a single 32-byte word, we extract `log2(x/n)` from the table by compute:
        //    prod1 = log2(x / n) = (x / n * table) >> 248
        //
        // 5. The final result is simply the sum of `prod0` and `prod1` calculated previously:
        //    log2(x) = log2(x / n) + log2(n) = prod0 + prod1
        //
        // @author Lohann Ferreira <developer@lohann.dev>
        unchecked {
            // Round `x` down to the closest power of 2 using an modified version of Seander's algorithm.
            // Reference: https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
            x |= x >> 1;
            x |= x >> 2;
            x |= x >> 4;
            x |= x >> 8;
            x |= x >> 16;
            x |= x >> 32;
            x |= x >> 64;
            x |= x >> 128;
            // note `x = 0` results in 1 here, when the closest power of two is actually zero given
            // `2**-infinity == 0` then we should do `(x >> 1) + toUint(x > 0)` instead, but this is not
            // necessary given `floor(log2(0)) == floor(log2(1))` anyway.
            x = (x >> 1) + 1;

            // 1. Compute `n = x mod 255`, given `x` is power of two the resulting `n` can only be one of the
            // following values: 1, 2, 4, 8, 16, 32, 64 or 128.
            uint256 n = x % 255;

            // 2. Compute `prod0 = log2(n)` using the OPCODE BYTE to lookup a 32-byte word, which we use as table.
            // Notice the last index in our table is 31, but `n` can be greater than 31, so first we map `n`
            // into an unique index between 0~31 by computing `n % 11`, as demonstrated below.

            //                   log2(n) Lookup Table
            // | n = x % 255 | index = n % 11 | table[index] = log2(n) |
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |       1     |   1 % 11 == 1  |   table[1] = log2(1)   |
            // |       2     |   2 % 11 == 2  |   table[2] = log2(2)   |
            // |       4     |   4 % 11 == 4  |   table[4] = log2(4)   |
            // |       8     |   8 % 11 == 8  |   table[8] = log2(8)   |
            // |      16     |  16 % 11 == 5  |   table[5] = log2(16)  |
            // |      32     |  32 % 11 == 10 |  table[10] = log2(32)  |
            // |      64     |  64 % 11 == 9  |   table[9] = log2(64)  |
            // |     128     | 128 % 11 == 7  |   table[7] = log2(128) |
            // Below we perform the table lookup, the table stores the result of `log2(n)`
            // in the corresponding byte at `index`.
            uint256 prod0;
            assembly ("memory-safe") {
                prod0 := byte(mod(n, 11), 0x0000010002040007030605000000000000000000000000000000000000000000)
            }

            // 4. Compute `prod1 = log2(x / n)`, notice `x / n` is a power of two multiple of 256, we use this
            // fact to build a very efficient lookup table using a single 32-byte word, described below:

            //                        log2(x/n) Lookup Table
            // |         x        | x / n | prod1 = log2(x/n) | index = log2(x/n) / 8 |
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
            // |  1   =< x < 2⁸   |  1    |    log2(1) == 0   |      0 / 8 == 0       |
            // |  2⁸  =< x < 2¹⁶  |  2⁸   |   log2(2⁸) == 8   |      8 / 8 == 1       |
            // |  2¹⁶ =< x < 2²⁴  |  2¹⁶  |  log2(2¹⁶) == 16  |     16 / 8 == 2       |
            // |  2²⁴ =< x < 2³²  |  2²⁴  |  log2(2²⁴) == 24  |     24 / 8 == 3       |
            // |        ...       |  ...  |        ...        |          ...          |
            // | 2²³² =< x < 2²⁴⁰ |  2²³² | log2(2²³²) == 232 |    232 / 8 == 29      |
            // | 2²⁴⁰ =< x < 2²⁴⁸ |  2²⁴⁰ | log2(2²⁴⁰) == 240 |    240 / 8 == 30      |
            // | 2²⁴⁸ =< x < 2²⁵⁶ |  2²⁴⁸ | log2(2²⁴⁸) == 248 |    248 / 8 == 31      |
            //
            // Notice compute `(x / n) * value` is equivalent to compute `value << (index * 8)`, we use this fact
            // to build a single 32-byte word using `table[index] = log2(x/n)`, then multiply the table by `x/n`
            // moves the result to the most significant byte, finally extract `log2(x/n) by shift right the table.
            //
            // prod1 = log2(x / n) = (x / n * table) >> 248
            uint256 prod1 = x >> prod0;
            prod1 *= 0x0008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f8;
            prod1 >>= 248;

            // 5. Sum both values to get the final result:
            // log2(x) = log2(x / n) + log2(n) = prod0 + prod1
            return prod0 + prod1;
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

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     * Throws if result overflows a uint256 or denominator == 0.
     *
     * @dev This this an modified version of the original implementation by OpenZeppelin SDK, which is released under MIT.
     * original: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/math/Math.sol#L117-L202
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            // Compute remainder.
            // - Rounding.Floor   then remainder is 0
            // - Rounding.Nearest then remainder is denominator / 2
            // - Rounding.Ceil    then remainder is denominator - 1
            uint256 remainder = denominator;
            remainder *= toUint(rounding != Rounding.Floor);
            remainder >>= toUint(rounding == Rounding.Nearest);
            remainder -= toUint(rounding == Rounding.Ceil);

            // 512-bit multiply [prod1 prod0] = x * y + remainder.
            // Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use the Chinese Remainder Theorem to reconstruct
            // the 512 bit result. The result is stored in two 256 variables such that product = prod1 * 2²⁵⁶ + prod0.
            uint256 prod0 = x * y; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))

                // Only round up if the final result is less than 2²⁵⁶.
                remainder := mul(remainder, lt(prod1, denominator))

                // Add 256 bit remainder to 512 bit number.
                // Cannot overflow once (2²⁵⁶ - 1)² + 2²⁵⁶ - 1 < 2⁵¹².
                mm := add(prod0, remainder)
                prod1 := add(prod1, lt(mm, prod0))
                prod0 := mm
            }

            // Make sure the result is less than 2**256. Also prevents denominator == 0.
            require(prod1 < denominator, "muldiv overflow");

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            assembly {
                // Compute remainder using addmod and mulmod.
                remainder := addmod(remainder, mulmod(x, y, denominator), denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            return prod0 * inverse;
        }
    }
}
