// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/DeploymentAuthorization.sol)
pragma solidity >=0.8.20;

import {BranchlessMath} from "./BranchlessMath.sol";

library DeploymentAuthorization {
    uint8 internal constant CHECK_ADDRESS = 1 << 0;
    uint8 internal constant CHECK_CODEHASH = 1 << 1;
    uint8 internal constant CHECK_CHAINID = 1 << 2;
    uint8 internal constant CHECK_MORTALITY = 1 << 3;
    uint8 internal constant CHECK_BALANCE = 1 << 4;
    uint8 internal constant ALLOW_CALLBACK = 1 << 5;
    uint8 internal constant ENFORCE_SELECTOR = 1 << 6;

    type DeploymentOptions is uint8;

    enum CallbackOptions {
        DISALLOWED,
        ALLOWED,
        REQUIRED,
        CHECK_SELECTOR
    }

    /**
     * @dev Network info stored in the Gateway Contract
     * @param domainSeparator Domain EIP-712 - Replay Protection Mechanism.
     * @param gasLimit The maximum amount of gas we allow on this particular network.
     * @param relativeGasPrice Gas price of destination chain, in terms of the source chain token.
     * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
     */
    struct Settings {
        DeploymentOptions options;
        address implementation;
        uint64 chainId;
        uint16 networkId;
        uint16 mortality;
        uint64 ancientBlockNumber;
        bytes32 ancientBlockHash;
        bytes32 implementationCodeHash;
        bytes4 initializerSelector;
        bool hasInitializer;
        uint256 initialBalance;
    }

    function _setBitflag(bool enabled, uint256 bitflags, uint256 flag) private pure returns (uint256) {
        uint256 set = bitflags | flag;
        uint256 unset = bitflags & ~flag;
        return BranchlessMath.ternary(enabled, set, unset);
    }

    /**
     * @dev Enable/Disable address check.
     */
    function checkAddress(DeploymentOptions bitflags, bool enabled) internal pure returns (DeploymentOptions) {
        uint256 updated = _setBitflag(enabled, uint256(DeploymentOptions.unwrap(bitflags)), CHECK_ADDRESS);
        return DeploymentOptions.wrap(uint8(updated));
    }

    /**
     * @dev Returns wether the address check is enabled or not.
     */
    function checkAddress(DeploymentOptions bitflags) internal pure returns (bool) {
        return DeploymentOptions.unwrap(bitflags) & CHECK_ADDRESS != 0;
    }

    /**
     * @dev Enable/Disable codehash check.
     */
    function checkCodehash(DeploymentOptions bitflags, bool enabled) internal pure returns (DeploymentOptions) {
        uint256 updated = _setBitflag(enabled, uint256(DeploymentOptions.unwrap(bitflags)), CHECK_CODEHASH);
        return DeploymentOptions.wrap(uint8(updated));
    }

    /**
     * @dev Returns wether the codehash check is enabled or not.
     */
    function checkCodehash(DeploymentOptions bitflags) internal pure returns (bool) {
        return DeploymentOptions.unwrap(bitflags) & CHECK_CODEHASH != 0;
    }

    /**
     * @dev Enable/Disable codehash check.
     */
    function checkChainID(DeploymentOptions bitflags, bool enabled) internal pure returns (DeploymentOptions) {
        uint256 updated = _setBitflag(enabled, uint256(DeploymentOptions.unwrap(bitflags)), CHECK_CHAINID);
        return DeploymentOptions.wrap(uint8(updated));
    }

    /**
     * @dev Returns wether the codehash check is enabled or not.
     */
    function checkChainID(DeploymentOptions bitflags) internal pure returns (bool) {
        return DeploymentOptions.unwrap(bitflags) & CHECK_CHAINID != 0;
    }

    /**
     * @dev Enable/Disable mortality check.
     */
    function checkMortality(DeploymentOptions bitflags, bool enabled) internal pure returns (DeploymentOptions) {
        uint256 updated = _setBitflag(enabled, uint256(DeploymentOptions.unwrap(bitflags)), CHECK_MORTALITY);
        return DeploymentOptions.wrap(uint8(updated));
    }

    /**
     * @dev Returns wether the mortality check is enabled or not.
     */
    function checkMortality(DeploymentOptions bitflags) internal pure returns (bool) {
        return DeploymentOptions.unwrap(bitflags) & CHECK_MORTALITY != 0;
    }

    /**
     * @dev Enable/Disable codehash check.
     */
    function checkBalance(DeploymentOptions bitflags, bool enabled) internal pure returns (DeploymentOptions) {
        uint256 updated = _setBitflag(enabled, uint256(DeploymentOptions.unwrap(bitflags)), CHECK_BALANCE);
        return DeploymentOptions.wrap(uint8(updated));
    }

    /**
     * @dev Returns wether the codehash check is enabled or not.
     */
    function checkBalance(DeploymentOptions bitflags) internal pure returns (bool) {
        return DeploymentOptions.unwrap(bitflags) & CHECK_BALANCE != 0;
    }

    /**
     * @dev Overwrite callback options.
     */
    function setCallOptions(DeploymentOptions bitflags, CallbackOptions options)
        internal
        pure
        returns (DeploymentOptions)
    {
        uint256 updated = DeploymentOptions.unwrap(bitflags) & 0x30;
        updated |= uint256(options) << 5;
        return DeploymentOptions.wrap(uint8(updated));
    }

    /**
     * @dev Returns the current defined callback options.
     */
    function callbackOptions(DeploymentOptions bitflags) internal pure returns (CallbackOptions) {
        return CallbackOptions((DeploymentOptions.unwrap(bitflags) >> 5) & 0x03);
    }

    /**
     * @dev Returns the current defined callback options.
     */
    function setCallbackOptions(Settings memory settings, CallbackOptions options, bytes4 selector) internal pure {
        settings.initializerSelector = selector;
        settings.options = setCallOptions(settings.options, options);
    }

    /**
     * @dev Returns the current defined callback options.
     */
    function callbackOptions(Settings memory settings) internal pure returns (CallbackOptions, bytes4) {
        CallbackOptions options = callbackOptions(settings.options);
        return (options, settings.initializerSelector);
    }

    // function encode(Settings memory settings) internal pure returns (bytes memory) {
    //     DeploymentOptions options = settings.options;
    //     uint256 size = 0;
    //     unchecked {
    //         // Address 160-bits
    //         size += 160 * BranchlessMath.toUint(checkAddress(options));

    //         // Codehash 256-bits
    //         size += 256 * BranchlessMath.toUint(checkCodehash(options));

    //         // ChainID 64-bits
    //         size += 64 * BranchlessMath.toUint(checkChainID(options));

    //         // Mortality 16-bits
    //         size += 16 * BranchlessMath.toUint(checkMortality(options));

    //         // Balance 256-bits
    //         size += 256 * BranchlessMath.toUint(checkBalance(options));
    //     }
    // }
}
