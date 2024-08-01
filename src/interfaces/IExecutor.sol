// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/interfaces/IExecutor.sol)

pragma solidity >=0.8.0;

import {Signature, GmpMessage, TssKey, GmpStatus, GmpStatus, UpdateKeysMessage, GmpSender} from "../Primitives.sol";

/**
 * @dev Required interface of an Gateway compliant contract
 */
interface IExecutor {
    /**
     * @dev Emitted when `GmpMessage` is executed.
     * @param id EIP-712 hash of the `GmpPayload`, which is it's unique identifier
     * @param source sender pubkey/address (the format depends on src chain)
     * @param dest recipient address
     * @param status GMP message execution status
     * @param result GMP result
     */
    event GmpExecuted(
        bytes32 indexed id, GmpSender indexed source, address indexed dest, GmpStatus status, bytes32 result
    );

    /**
     * @dev Emitted when `UpdateShardsMessage` is executed.
     * @param id EIP-712 hash of the `UpdateShardsMessage`
     * @param revoked shard's keys revoked
     * @param registered shard's keys registered
     */
    event KeySetChanged(bytes32 indexed id, TssKey[] revoked, TssKey[] registered);

    /**
     * Execute GMP message
     * @param signature Schnorr signature
     * @param message GMP message
     */
    function execute(Signature calldata signature, GmpMessage calldata message)
        external
        returns (GmpStatus status, bytes32 result);

    /**
     * Update TSS key set
     * @param signature Schnorr signature
     * @param message Shard's keys to register and revoke
     */
    function updateKeys(Signature memory signature, UpdateKeysMessage memory message) external;
}
