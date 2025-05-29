// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/GasUtils.sol)

pragma solidity >=0.8.20;

import {BranchlessMath} from "./utils/BranchlessMath.sol";

/**
 * @dev Utilities for compute the GMP gas price, gas cost and gas needed.
 */
library GasUtils {
    using BranchlessMath for uint256;

    function estimateBaseGas(uint256 messageSize) internal pure returns (uint256) {
        uint256 calldataSize = messageSize.align32() + 676; // selector + Signature + Batch
        return 21000 + calldataSize * 16; // assume every byte is a 1
    }

    /**
     * @dev Estimate the gas cost of a GMP message.
     * @param messageSize The message size.
     * @param gasLimit The message gas limit.
     */
    function estimateGas(uint16 messageSize, uint64 gasLimit) internal pure returns (uint256) {
        unchecked {
            uint256 calldataSize = uint256(messageSize).align32() + 676; // selector + Signature + Batch
            uint256 messageWords = _toWord(messageSize);
            uint256 calldataWords = _toWord(calldataSize);
            // destination contract gas limit
            uint256 gas = uint256(gasLimit);
            // proxy overhead
            gas += proxyOverheadGas(calldataSize, 0);
            // cost of calldata copy
            gas += messageWords * 3;
            // cost of hashing the payload
            gas += messageWords * 6;
            // execution base cost
            gas += 46606;
            // memory expansion cost
            gas += memoryExpansionGas(calldataWords);
            // cost of countNonZerosCalldata
            gas += (calldataWords * 106) + (((calldataWords - 255 + 254) / 255) * 214);
            return gas;
        }
    }

    /**
     * @dev Compute the amount of gas used by the `GatewayProxy`.
     * @param calldataLen The length of the calldata in bytes
     * @param returnLen The length of the return data in bytes
     */
    function proxyOverheadGas(uint256 calldataLen, uint256 returnLen) internal pure returns (uint256) {
        unchecked {
            // Convert the calldata and return data length to words
            calldataLen = _toWord(calldataLen);
            returnLen = _toWord(returnLen);

            // Base cost: OPCODES + COLD SLOAD + COLD DELEGATECALL + RETURNDATACOPY
            // uint256 gasCost = 57 + 2100 + 2600;
            uint256 gasCost = 31 + 2100 + 2600 + 32 + 66;

            // CALLDATACOPY
            gasCost = gasCost.saturatingAdd(calldataLen * 3);

            // RETURNDATACOPY
            gasCost = gasCost.saturatingAdd(returnLen * 3);

            // MEMORY EXPANSION (minimal 3 due mstore(0x40, 0x80))
            uint256 words = calldataLen.max(returnLen).max(3);
            gasCost = gasCost.saturatingAdd(memoryExpansionGas(words));
            return gasCost;
        }
    }

    /**
     * @dev Compute the gas cost of memory expansion.
     * @param words number of words, where a word is 32 bytes
     */
    function memoryExpansionGas(uint256 words) private pure returns (uint256) {
        unchecked {
            return (words.saturatingMul(words) >> 9).saturatingAdd(words.saturatingMul(3));
        }
    }

    /**
     * @dev Convert byte count to 256bit word count, rounded up.
     */
    function _toWord(uint256 byteCount) private pure returns (uint256 words) {
        assembly {
            words := add(shr(5, byteCount), gt(and(byteCount, 0x1f), 0))
        }
    }

    /**
     * @dev Compute the transaction base cost.
     */
    function txBaseGas() internal pure returns (uint256) {
        unchecked {
            uint256 nonZeros = countNonZerosCalldata(msg.data);
            uint256 zeros = msg.data.length - nonZeros;
            return 21000 + (nonZeros * 16) + (zeros * 4);
        }
    }

    /**
     * @dev Count the number of non-zero bytes from calldata.
     * gas cost = 224 + (words * 106) + (((words + 254) / 255) * 214)
     */
    function countNonZerosCalldata(bytes calldata data) internal pure returns (uint256 nonZeros) {
        assembly ("memory-safe") {
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
}
