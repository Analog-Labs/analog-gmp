// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/Float9x56.sol)

pragma solidity >=0.8.0;

import {BranchlessMath, Rounding} from "./BranchlessMath.sol";

/**
 * @dev Unsigned Float with 9 bit exponent and 56 bit fraction.
 * The values are represented by the formula `2**(e - 311) * fraction`, where `e` is the 9bit
 * exponent and `fraction` is the 56bit fraction, where the msb is alway set when `e > 0`.
 */
type UFloat9x56 is uint64;

library UFloatMath {
    using BranchlessMath for uint256;

    /**
     * @dev Constant representing 0.0 in UFloat9x56.
     */
    UFloat9x56 internal constant ZERO = UFloat9x56.wrap(0x0000000000000000);

    /**
     * @dev Constant representing 1.0 in UFloat9x56.
     */
    UFloat9x56 internal constant ONE = UFloat9x56.wrap(0x8000000000000000);

    /**
     * @dev Maximum value representable in UFloat9x56, i.e., 2**200 * (2**56 - 1).
     */
    UFloat9x56 internal constant MAX = UFloat9x56.wrap(0xffffffffffffffff);

    /**
     * @dev Default rounding mode for conversion functions.
     */
    Rounding internal constant DEFAULT_ROUNDING = Rounding.Nearest;

    /**
     * @dev Number of bits used to represent the mantissa.
     */
    uint256 internal constant MANTISSA_DIGITS = 56;

    /**
     * @dev Maximum value the mantissa can assume.
     */
    uint256 internal constant MANTISSA_MAX = uint64(2 ** MANTISSA_DIGITS - 1);

    /**
     * @dev Minimum value the mantissa can assume, lower than this value is considered a subnormal number.
     */
    uint256 internal constant MANTISSA_MIN = uint64(2 ** (MANTISSA_DIGITS - 1));

    /**
     * @dev The maximum value that can be represented by `UFloat9x56`.
     */
    uint256 internal constant MAX_VALUE = MANTISSA_MAX << (256 - MANTISSA_DIGITS);

    /**
     * @dev Mask to extract the mantissa from raw `UFloat9x56`.
     */
    uint256 private constant MANTISSA_MASK = uint64(MANTISSA_MAX >> 1);

    /**
     * @dev Position of the carry bit when converting uint256 to `UFloat9x56`.
     */
    uint256 private constant CARRY_BIT = 2 ** (256 - MANTISSA_DIGITS);

    /**
     * @dev multiply an UFloat9x56 by an uint256 in constant gas.
     */
    function mul(UFloat9x56 x, uint256 y) internal pure returns (uint256 result) {
        assembly {
            // Extract exponent and fraction
            let exponent := shr(55, x)
            let fraction := or(and(x, 0x007fffffffffffff), shl(55, gt(exponent, 0)))
            exponent := sub(exponent, sub(311, iszero(exponent)))
            fraction := shl(mul(exponent, sgt(exponent, 0)), fraction)

            // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1
            let mm := mulmod(y, fraction, not(0))
            let low := mul(y, fraction)
            let high := sub(sub(mm, low), lt(mm, low))

            // Shift low and high if exponent >= 256
            let shift := mul(sub(0, exponent), slt(exponent, 0))
            mm := gt(shift, 255)
            low := xor(low, mul(xor(low, high), mm))
            high := mul(high, iszero(mm))

            // make sure shift is between 0 and 255
            shift := mod(shift, 256)

            // Combine high and low
            high := shl(sub(256, shift), high)
            low := shr(shift, low)
            result := or(high, low)
        }
    }

    /**
     * @dev Saturating multiplication, bounds to `2 ** 256 - 1` instead of overflowing.
     */
    function saturatingMul(UFloat9x56 x, uint256 y) internal pure returns (uint256 result) {
        assembly {
            // Extract exponent and fraction
            let exponent := shr(55, x)
            let fraction := or(and(x, 0x007fffffffffffff), shl(55, gt(exponent, 0)))
            exponent := sub(exponent, sub(311, iszero(exponent)))
            fraction := shl(mul(exponent, sgt(exponent, 0)), fraction)

            // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1
            let mm := mulmod(y, fraction, not(0))
            let low := mul(y, fraction)
            let high := sub(sub(mm, low), lt(mm, low))

            // Shift low and high if exponent >= 256
            let shift := mul(sub(0, exponent), slt(exponent, 0))
            mm := gt(shift, 255)
            low := xor(low, mul(xor(low, high), mm))
            high := mul(high, iszero(mm))

            // make sure shift is between 0 and 255
            shift := mod(shift, 256)

            // Combine high and low
            mm := iszero(shr(shift, high)) // detect overflow
            high := shl(sub(256, shift), high)
            low := shr(shift, low)
            result := or(high, low)
            result := or(result, sub(mm, 1)) // saturate if overflow
        }
    }

    /**
     * @dev Returns the mantissa and base 2 exponent as integers, respectively.
     * The original number can be recovered by `mantissa * 2 ** exponent`.
     * Returns (0, -311) if the value is zero.
     */
    function decode(UFloat9x56 value) internal pure returns (uint64 mantissa, int16 exponent) {
        // Extract the exponent
        exponent = int16(int64(UFloat9x56.unwrap(value) >> uint64(MANTISSA_DIGITS - 1)));

        // Extract the mantissa
        mantissa = UFloat9x56.unwrap(value) & uint64(MANTISSA_MASK);

        // If the value is subnormal, then the exponent is -310 and mantissa msb is not set.
        bool isSubnormal = exponent == 0;
        mantissa |= uint64(BranchlessMath.toUint(!isSubnormal) << (MANTISSA_DIGITS - 1));
        exponent += int16(int256(BranchlessMath.toUint(isSubnormal && mantissa > 0)));

        // Exponent bias + mantissa shift
        exponent -= 256 + int16(uint16(MANTISSA_DIGITS - 1));
    }

    /**
     * @dev Compare if `UFloat9x56` is equal to another integer, considering only the mantissa bits.
     */
    function eq(UFloat9x56 x, uint256 y) internal pure returns (bool r) {
        uint256 mantissa;
        int256 exponent;
        (mantissa, exponent) = decode(x);
        unchecked {
            // Shift y if the exponent is negative
            uint256 shift = BranchlessMath.abs(exponent) * BranchlessMath.toUint(exponent < 0 && mantissa > 0);
            mantissa >>= shift;
            shift = uint256(exponent) * BranchlessMath.toUint(exponent > 0);
            return (y & (type(uint256).max << shift)) == (mantissa << shift);
        }
    }

    /**
     * @dev Returns the integer part. This means that non-integer numbers are always truncated towards zero
     * This function always returns the precise result.
     */
    function truncate(UFloat9x56 value) internal pure returns (uint256) {
        uint256 mantissa;
        int256 exponent;
        (mantissa, exponent) = decode(value);
        unchecked {
            uint256 shift = BranchlessMath.abs(exponent) * BranchlessMath.toUint(exponent < 0 && mantissa > 0);
            mantissa >>= shift;
            shift = uint256(exponent) * BranchlessMath.toUint(exponent > 0);
            mantissa <<= shift;
            return mantissa;
        }
    }

    /**
     * @dev Converts uint256 to `UFloat9x56`, following the selected rounding direction.
     * By default, it rounds to the nearest value.
     */
    function fromUint(uint256 value) internal pure returns (UFloat9x56) {
        return fromUint(value, DEFAULT_ROUNDING);
    }

    /**
     * @dev Converts uint256 to `UFloat9x56`, following the selected rounding direction.
     * IMPORTANT: Always round down if the value is greater than `MAX_VALUE`.
     */
    function fromUint(uint256 value, Rounding rounding) internal pure returns (UFloat9x56) {
        unchecked {
            // Compute the exponent, if `value > 0` then the exponent cannot be less than 2**-55.
            uint256 exponent = BranchlessMath.log2(value) + 256;

            // Normalize mantissa by removing leading zeros, this step make sure the `CARRY_BIT`
            // is always in the same position for any given value.
            uint256 mantissa = value << (511 - exponent);

            // Set carry bit based on selected rouding direction.
            uint256 carry = CARRY_BIT;
            carry *= BranchlessMath.toUint(rounding != Rounding.Floor && value < MAX_VALUE);
            carry -= BranchlessMath.toUint(rounding == Rounding.Ceil && carry > 0);
            carry >>= BranchlessMath.toUint(rounding == Rounding.Nearest);
            carry += mantissa & (CARRY_BIT - 1);
            carry = BranchlessMath.toUint(carry >= CARRY_BIT);

            // Shift mantissa to a 56 bit integer then add the carry bit.
            mantissa >>= 256 - MANTISSA_DIGITS;
            mantissa += carry;

            // Increment the exponent if mantissa overflow after adding the carry bit.
            carry = BranchlessMath.toUint(mantissa > MANTISSA_MAX);
            mantissa >>= carry;
            exponent += carry;

            // If the value is zero, then the exponent must be -311.
            exponent *= BranchlessMath.toUint(value > 0);

            // Encode mantissa and exponent into `UFloat9x56`
            mantissa &= MANTISSA_MAX >> 1;
            exponent <<= MANTISSA_DIGITS - 1;
            return UFloat9x56.wrap(uint64(mantissa) | uint64(exponent));
        }
    }

    /**
     * @dev Converts numerator / denominator to `UFloat9x56`, following the selected rounding direction.
     */
    function fromRational(uint256 numerator, uint256 denominator) internal pure returns (UFloat9x56) {
        return fromRational(numerator, denominator, DEFAULT_ROUNDING);
    }

    /**
     * @dev Converts numerator / denominator to `UFloat9x56`, following the selected rounding direction.
     */
    function fromRational(uint256 numerator, uint256 denominator, Rounding rounding)
        internal
        pure
        returns (UFloat9x56)
    {
        unchecked {
            int256 exponent;
            {
                // Remove leading zeros from numerator and denominator
                uint256 numbits = BranchlessMath.log2(numerator);
                uint256 denbits = BranchlessMath.log2(denominator);
                numerator <<= 255 - numbits;
                denominator <<= 255 - denbits;

                // Compute exponent
                exponent = int256(numbits) - int256(denbits);
            }

            // If `(numerator / denominator) <= 2**-255` then it is subnormal number
            bool isSubnormal = numerator > 0 && exponent <= -255;

            // Adjust the exponent to guarantee the mantissa most significant bit is set
            uint256 shift = MANTISSA_DIGITS;
            shift -= BranchlessMath.toUint(numerator >= denominator || isSubnormal);
            exponent -= int256(shift);

            // Compute (numerator * 2**exponent) / denominator
            uint256 mantissa = BranchlessMath.mulDiv(numerator, 1 << shift, denominator, rounding);

            // Adjust mantissa and expoennt when it exceeds 56 bits, this is only possible when
            // all mantissa bits are set and the value is rounded up, as described below.
            // ```solidity
            // UFloatMath.fromRational(0x2ffffffffffffff, 3, Rounding.Floor) == (2**0 * 0xffffffffffffff)
            // UFloatMath.fromRational(0x2ffffffffffffff, 3, Rounding.Ceil)  == (2**1 * 0x80000000000000)
            // ```
            shift = BranchlessMath.toUint(mantissa > MANTISSA_MAX);
            mantissa >>= shift;
            exponent += int256(shift);

            // If the mantissa is zero, then the exponent is the minimum value.
            exponent = BranchlessMath.ternary(mantissa == 0, -311, exponent);

            // Adjust exponent to fit in 9 bits
            exponent += 311 - int256(BranchlessMath.toUint(isSubnormal));
            exponent <<= MANTISSA_DIGITS - 1;

            // Remove mantissa most significant bit
            mantissa &= MANTISSA_MAX >> 1;

            return UFloat9x56.wrap(uint64(mantissa) | uint64(uint256(exponent)));
        }
    }

    /**
     * @dev Convert `UFloat9x56` to a rational number, expressed as numerator / denominator.
     * Obs: Values above 2**-256 are represented precisely, values below are approximated or round down to zero.
     */
    function toRational(UFloat9x56 value) internal pure returns (uint256 numerator, uint256 denominator) {
        unchecked {
            if (UFloat9x56.unwrap(value) == 0) {
                return (0, 1);
            }

            int256 exponent;
            (numerator, exponent) = decode(value);

            // Remove trailing zeros from mantissa.
            {
                uint256 trailingZeros = BranchlessMath.trailingZeros(numerator);
                trailingZeros *= BranchlessMath.toUint(exponent < 0);
                exponent += int256(trailingZeros);
                numerator >>= trailingZeros;
            }

            if (exponent > 0) {
                // The exponent is positive, cannot overflow once the maximum exponent is 200.
                // Calculates: (mantissa * 2**exponent) / 1
                numerator <<= uint256(exponent);
                denominator = 1;
            } else if (exponent > -256) {
                // The exponent is negative, so we shift the denominator and keep the numerator.
                // Calculates: mantissa / 2**exponent
                denominator = 1 << uint256(-exponent);
            } else {
                // Is not possible to represent such tiny values accurately given the denominator has more than 256 bit,
                // but is still possible to get a good aproximation if we set the numerator to one:
                // Calculates: 1 / (2**-exponent / mantissa)
                //
                // The final exponent is computed as a product of two exponents:
                // 2**-exponent == 2**exp0 * 2*exp1
                uint256 exp0 = 255;
                uint256 exp1 = BranchlessMath.abs(exponent) - exp0;

                // If numerator is less or equal to `2**exp1`, then the denominator has more than 256bit, so return zero.
                if (exp1 >= numerator) {
                    return (1, 0);
                }

                // Compute full 512 bit multiplication and division as (2**exp0 * 2**exp1) / mantissa.
                denominator = BranchlessMath.mulDiv(1 << exp0, 1 << exp1, numerator, Rounding.Floor);

                // Handle the case where the denominator is round towards zero.
                numerator = BranchlessMath.toUint(denominator > 0);
                denominator |= BranchlessMath.toUint(denominator == 0);
            }
        }
    }
}
