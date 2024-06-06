// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/GatewayProxy.sol)

pragma solidity >=0.8.0;

import {ERC1967} from "./utils/ERC1967.sol";

contract GatewayProxy {
    /**
     * @dev Minimal EIP-1967 proxy bytecode.
     */
    bytes private constant PROXY_BYTECODE =
        hex"363d3d373d3d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d82803e903d91603857fd5bf3";

    constructor(address implementation, bytes memory initializer) payable {
        // Copy Proxy bytecode to memory
        bytes memory bytecode = PROXY_BYTECODE;

        // Store the address of the implementation contract
        ERC1967.setImplementation(implementation);

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
