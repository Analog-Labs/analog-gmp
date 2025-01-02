// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/Hashing.sol)

pragma solidity >=0.8.20;

library Hashing {
    /**
     * @dev Hashes a single 256-bit integer without memory allocation.
     */
    function hash(uint256 a) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            h := keccak256(0x00, 0x20)
        }
    }

    /**
     * @dev Hashes two 256-bit words without memory allocation.
     */
    function hash(uint256 a, uint256 b) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            h := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Hashes three 256-bit words without memory allocation.
     *
     * To store the third word this method backup and retored the reserved memory location `0x40`.
     * Reference: https://docs.soliditylang.org/en/v0.8.28/internals/layout_in_memory.html
     */
    function hash(uint256 a, uint256 b, uint256 c) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)

            // Backup the free memory pointer
            let freeMemBackup := mload(0x40)

            mstore(0x40, c)
            h := keccak256(0x00, 0x60)

            // Restore the free memory pointer
            mstore(0x40, freeMemBackup)
        }
    }

    /**
     * @dev Hashes four 256-bit words without memory allocation.
     *
     * To store the last two words this method backup and retored the reserved memory location `0x40` and `0x80`.
     * Reference: https://docs.soliditylang.org/en/v0.8.28/internals/layout_in_memory.html
     */
    function hash(bytes32 a, bytes32 b, bytes32 c, bytes32 d) internal pure returns (bytes32) {
        return hash(uint256(a), uint256(b), uint256(c), uint256(d));
    }

    /**
     * @dev Hashes four 256-bit words without memory allocation.
     *
     * To store the last two words this method backup and retored the reserved memory location `0x40` and `0x80`.
     * Reference: https://docs.soliditylang.org/en/v0.8.28/internals/layout_in_memory.html
     */
    function hash(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)

            // Backup the free memory pointer
            let freeMemBackup := mload(0x40)
            mstore(0x40, c)
            {
                // Backup the scratch space 0x60
                let backup := mload(0x60)

                // Compute the hash
                mstore(0x60, d)
                h := keccak256(0x00, 0x80)

                // Restore the scratch space 0x60
                mstore(0x60, backup)
            }
            // Restore the free memory pointer
            mstore(0x40, freeMemBackup)
        }
    }
}
