// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/Float9x56.sol)

pragma solidity >=0.8.0;

/**
 * @dev Unsigned Float with 9 bit exponent and 56 bit fraction.
 * The values are represented by the formula `2^(e - 311) * fraction`, where `e` is the 9bit
 * exponent and `fraction` is the 56bit fraction (where the msb is alway set).
 */
type UFloat9x56 is uint64;

library UFloatMath {
    UFloat9x56 internal constant ONE = UFloat9x56.wrap(0xff00000000000000);

    /**
     * @dev multiply an UFloat9x56 by an uint256 in constant gas.
     */
    function mul(UFloat9x56 x, uint256 y) internal pure returns (uint256 result) {
        assembly {
            // Extract exponent and fraction
            let exponent := sub(shr(55, x), 311)
            let fraction := or(and(x, 0x007fffffffffffff), 0x0080000000000000)
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
     * @dev Convert the float to a rational number.
     */
    function toRational(UFloat9x56 value) internal pure returns (uint256 numerator, uint256 denominator) {
        unchecked {
            if (UFloat9x56.unwrap(value) == 0) {
                return (0, 1);
            }
            int256 exponent = int256(uint256(UFloat9x56.unwrap(value)) >> 55) - 311;
            numerator = (uint256(UFloat9x56.unwrap(value)) & 0x007fffffffffffff) | 0x0080000000000000;
            if (exponent < 0) {
                // The exponent is negative, so we need to shift the denominator.
                exponent = -exponent;
                if (exponent > 255) {
                    // OBS: Is not possible to acurately represent such tiny values precisely.
                    // so this is just an approximation.
                    exponent -= 255;
                    denominator = (1 << 255) / numerator;
                    denominator <<= uint256(exponent);
                    numerator = 1;
                } else {
                    denominator = 1 << uint256(exponent);
                }
            } else {
                numerator <<= uint256(exponent);
                denominator = 1;
            }
        }
    }
}
