// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/GatewayProxy.sol)

pragma solidity >=0.8.0;

import {ERC1967} from "./utils/ERC1967.sol";

contract GatewayProxy {
    /**
     * @dev EIP-1967 storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1.
     * Ref: https://eips.ethereum.org/EIPS/eip-1967
     */
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address admin) payable {
        // Set the ERC1967 admin.
        ERC1967.setAdmin(admin);
    }

    function upgrade(address newImplementation) external payable {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");

        // Store the address of the implementation contract
        ERC1967.setImplementation(newImplementation);
    }

    receive() external payable {}

    fallback() external payable {
        assembly ("memory-safe") {
            // Copy the calldata to memory
            calldatacopy(0, 0, calldatasize())

            // Delegate call to the implementation contract
            let success := delegatecall(gas(), sload(IMPLEMENTATION_SLOT), 0, calldatasize(), 0, 0)

            // Copy the return data to memory
            returndatacopy(0, 0, returndatasize())

            // Return if the call succeeded
            if success { return(0, returndatasize()) }

            // Revert if the call failed
            revert(0, returndatasize())
        }
    }
}
