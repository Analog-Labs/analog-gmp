// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/Hashing.sol)

pragma solidity >=0.8.20;

library Hashing {
    /**
     * @dev Solidity's reserved location for the free memory pointer.
     * Reference: https://docs.soliditylang.org/en/v0.8.28/internals/layout_in_memory.html
     */
    uint256 internal constant ALLOCATED_MEMORY = 0x40;

    /**
     * @dev Hashes two 256-bit words without memory allocation, uses the memory between 0x00~0x40.
     */
    function hash(uint256 a, uint256 b) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            h := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Hashes three 256-bit words without memory allocation, uses the memory between 0x00~0x60.
     *
     * The reserverd memory region `0x40~0x60` is restored to its previous state after execution.
     * See https://docs.soliditylang.org/en/v0.8.28/internals/layout_in_memory.html for more details.
     */
    function hash(uint256 a, uint256 b, uint256 c) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)

            // Backup the free memory pointer
            let freeMemBackup := mload(ALLOCATED_MEMORY)

            mstore(ALLOCATED_MEMORY, c)
            h := keccak256(0x00, 0x60)

            // Restore the free memory pointer
            mstore(ALLOCATED_MEMORY, freeMemBackup)
        }
    }
}
