// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/ERC1967.sol)

pragma solidity >=0.8.0;

/// @title Minimal implementation of ERC1967 storage slot
library ERC1967 {
    // bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function load() internal view returns (address implementation) {
        assembly {
            implementation := sload(_IMPLEMENTATION_SLOT)
        }
    }

    function store(address implementation) internal {
        assembly {
            sstore(_IMPLEMENTATION_SLOT, implementation)
        }
    }
}
