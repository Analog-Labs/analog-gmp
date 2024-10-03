// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/GatewayProxy.sol)

pragma solidity >=0.8.0;

import {ERC1967} from "./utils/ERC1967.sol";
import {Context, CreateKind, IUniversalFactory} from "@universal-factory/IUniversalFactory.sol";

contract GatewayProxy {
    /**
     * @dev The address of the `UniversalFactory` contract, must be the same on all networks.
     */
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x0000000000001C4Bf962dF86e38F0c10c7972C6E);

    /**
     * @dev Minimal ERC-1967 proxy bytecode.
     */
    bytes private constant PROXY_BYTECODE =
        hex"363d3d373d3d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d82803e903d91603857fd5bf3";

    constructor(address admin) payable {
        // This contract must be deployed by the `UniversalFactory`
        Context memory ctx = FACTORY.context();
        require(ctx.contractAddress == address(this), "Only the UniversalFactory can deploy this contract");
        require(ctx.kind == CreateKind.CREATE2, "Only CREATE2 is allowed");

        require(ctx.data.length > 0, "ctx.data cannot be empty length");
        require(ctx.data.length >= 128, "unexpected ctx.data format, expected 128 bytes");

        // Store the address of the implementation contract
        // DeploymentAuthorization memory authorization;
        uint8 v;
        bytes32 r;
        bytes32 s;
        address implementation;
        (v, r, s, implementation) = abi.decode(ctx.data, (uint8, bytes32, bytes32, address));

        // Verify the signature
        bytes32 digest = keccak256(abi.encode(address(this), implementation));
        require(admin == ecrecover(digest, v, r, s), "invalid signature");

        // Set the ERC1967 admin.
        ERC1967.setAdmin(admin);

        // Set the ERC1967 implementation.
        ERC1967.setImplementation(implementation);

        // Verify the chain id.
        // require(authorization.chainId == block.chainid);

        // {
        //     // Verify the signature
        //     bytes32 domainSeparator = computeDomainSeparator(block.chainid, address(this));
        //     bytes32 authHash = eip712hash(domainSeparator, authorization);
        //     authHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, authHash));
        //     require(admin == ecrecover(authHash, v, r, s));
        // }

        // // Check wether the initializer callback is required or not.
        // if (authorization.hasInitializer) {
        //     require(ctx.hasCallback && ctx.callbackSelector == authorization.initializerSelector);
        // }

        // // Check the initial balance, if it's not `type(uint256).max`.
        // if (authorization.initialBalance != type(uint256).max) {
        //     require(msg.value == authorization.initialBalance);
        // }

        // // (optional) Check the implementation contract code hash
        // if (authorization.implementationCodeHash != bytes32(0)) {
        //     address implementation = authorization.implementation;
        //     bytes32 codehash;
        //     assembly {
        //         codehash := extcodehash(implementation)
        //     }
        //     require(codehash == authorization.implementationCodeHash);
        // }

        // // This signature is valid only after `ancientBlockNumber`.
        // require(block.number >= authorization.ancientBlockNumber);

        // // Check the ancient block hash if the gap is less than 256 blocks and
        // // the ancient block hash is not empty.
        // uint256 diff = block.number - authorization.ancientBlockNumber;
        // require(
        //     authorization.ancientBlockHash == bytes32(0) || diff > 255
        //         || authorization.ancientBlockHash == blockhash(authorization.ancientBlockNumber)
        // );

        // Check the mortality of this transaction.
        // require(authorization.mortality == 0 || diff < authorization.mortality);

        // Copy Proxy bytecode to memory
        bytes memory bytecode = PROXY_BYTECODE;

        // Return the `PROXY_BYTECODE`.
        /// @solidity memory-safe-assembly
        assembly {
            return(add(bytecode, 32), mload(bytecode))
        }
    }

    // Computes the EIP-712 domain separador
    // function computeDomainSeparator(uint256 chainid, address addr) private pure returns (bytes32) {
    //     return keccak256(
    //         abi.encode(
    //             keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    //             keccak256("Analog Gateway Proxy Contract"),
    //             keccak256("1.0.0"),
    //             chainid,
    //             addr
    //         )
    //     );
    // }
}
