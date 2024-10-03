// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/Float9x56.sol)

pragma solidity >=0.8.0;

import {BranchlessMath, Rounding} from "./BranchlessMath.sol";

/**
 * @dev Library for fixed-point arithmetic in the form of a 9.56-bit fixed-point number.
 */
library Encoder {
    using BranchlessMath for uint256;

    type RawPointer is uint256;

    function encodeU8(RawPointer ptr, uint8 value) internal pure returns (RawPointer out) {
        assembly {
            mstore8(ptr, value)
            out := add(ptr, 1)
        }
    }

    function encodeU16(RawPointer ptr, uint16 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(240, value))
            out := add(ptr, 2)
        }
    }

    function encodeU24(RawPointer ptr, uint24 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(232, value))
            out := add(ptr, 3)
        }
    }

    function encodeU32(RawPointer ptr, uint32 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(224, value))
            out := add(ptr, 4)
        }
    }

    function encodeU40(RawPointer ptr, uint40 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(216, value))
            out := add(ptr, 5)
        }
    }

    function encodeU48(RawPointer ptr, uint48 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(208, value))
            out := add(ptr, 6)
        }
    }

    function encodeU56(RawPointer ptr, uint56 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(200, value))
            out := add(ptr, 7)
        }
    }

    function encodeU64(RawPointer ptr, uint64 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(192, value))
            out := add(ptr, 8)
        }
    }

    function encodeU72(RawPointer ptr, uint72 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(184, value))
            out := add(ptr, 9)
        }
    }

    function encodeU80(RawPointer ptr, uint80 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(176, value))
            out := add(ptr, 10)
        }
    }

    function encodeU88(RawPointer ptr, uint88 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(176, value))
            out := add(ptr, 11)
        }
    }

    function encodeU128(RawPointer ptr, uint128 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, shl(128, value))
            out := add(ptr, 16)
        }
    }

    function encode(RawPointer ptr, uint256 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, value)
            out := add(ptr, 32)
        }
    }

    function encode(RawPointer ptr, bytes32 value) internal pure returns (RawPointer out) {
        assembly {
            mstore(ptr, value)
            out := add(ptr, 32)
        }
    }

    function compactLen(uint256 value) internal pure returns (uint256, uint8) {
        unchecked {
            uint256 mode = 0; // mode 0
            mode += BranchlessMath.toUint(value > 63); // mode 1
            mode += BranchlessMath.toUint(value > 16383); // mode 2
            mode += BranchlessMath.toUint(value > 1073741823); // mode 3

            uint256 size = (mode << 1) + BranchlessMath.toUint(mode == 0);
            uint256 mode4size = (16 - (BranchlessMath.leadingZeros(value) >> 3)) + 1;
            size = BranchlessMath.ternary(mode == 3, mode4size, size);

            return (size, uint8(mode));
        }
    }

    function encodeCompact(RawPointer ptr, uint256 value) internal pure returns (RawPointer out) {
        (uint256 len, uint8 mode) = compactLen(value);
        uint256 word1;
        uint256 word2;
        unchecked {
            uint256 mode4 = (value << 8) | (len << 2) | mode;
            uint256 other = (value << 2) | mode;
            word1 = BranchlessMath.ternary(mode == 4, mode4, other);
            word1 = BranchlessMath.swapEndianess(word1);
            word2 = BranchlessMath.ternary(mode == 4, value >> 248, value >> 254);
            word2 = BranchlessMath.swapEndianess(word2);
        }
        assembly {
            mstore(ptr, word1)
            mstore(add(ptr, 0x20), word2)
            out := add(ptr, len)
        }
    }
}
