// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/GatewayProxy.sol)

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

contract GatewayProxy {
    bytes private constant PROXY_BYTECODE =
        hex"365f5f375f5f365f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d5f5f3e6036573d5ffd5b3d5ff3";

    constructor(address implementation, bytes memory initializer) payable {
        require(implementation.code.length > 0, "not a contract");

        // Copy Proxy bytecode to memory
        bytes memory bytecode = PROXY_BYTECODE;

        // Store the address of the implementation contract
        ERC1967.store(implementation);

        // Initialize storage by calling the implementation's using `delegatecall`.
        bool success = true;
        bytes memory returndata = "";
        if (initializer.length > 0) {
            (success, returndata) = implementation.delegatecall(initializer);
        }

        // Verify initialization result
        /// @solidity memory-safe-assembly
        assembly {
            if success { return(add(bytecode, 32), mload(bytecode)) }
            revert(add(returndata, 32), mload(returndata))
        }
    }
}
