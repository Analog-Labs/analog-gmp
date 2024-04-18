// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Primitives.sol)

pragma solidity >=0.8.0;

/**
 * @dev Tss public key
 * @param yParity public key y-coord parity, the contract converts it to 27/28
 * @param xCoord affine x-coordinate
 */
struct TssKey {
    uint8 yParity;
    uint256 xCoord;
}

/**
 * @dev Schnorr signature.
 * OBS: what is actually signed is: keccak256(abi.encodePacked(R, parity, px, nonce, message))
 * Where `parity` is the public key y coordinate stored in the contract, and `R` is computed from `e` and `s` parameters.
 * @param xCoord public key x coordinates, y-parity is stored in the contract
 * @param e Schnorr signature e component
 * @param s Schnorr signature s component
 */
struct Signature {
    uint256 xCoord;
    uint256 e;
    uint256 s;
}

/**
 * @dev GMP payload, this is what the timechain creates as task payload
 * @param source Pubkey/Address of who send the GMP message
 * @param srcNetwork Source chain identifier (for ethereum networks it is the EIP-155 chain id)
 * @param dest Destination/Recipient contract address
 * @param destNetwork Destination chain identifier (it's the EIP-155 chain_id for ethereum networks)
 * @param gasLimit gas limit of the GMP call
 * @param salt Message salt, useful for sending two messages with same content
 * @param data message data with no specified format
 */
struct GmpMessage {
    bytes32 source;
    uint16 srcNetwork;
    address dest;
    uint16 destNetwork;
    uint256 gasLimit;
    uint256 salt;
    bytes data;
}

/**
 * @dev Message payload used to revoke or/and register new shards
 * @param revoke Shard's keys to revoke
 * @param register Shard's keys to register
 */
struct UpdateKeysMessage {
    TssKey[] revoke;
    TssKey[] register;
}

/**
 * @dev Message payload used to revoke or/and register new shards
 * @param revoke Shard's keys to revoke
 * @param register Shard's keys to register
 */
struct Network {
    uint16 id;
    address gateway;
}

/**
 * @dev Status of a GMP message
 */
enum GmpStatus {
    NOT_FOUND,
    SUCCESS,
    REVERT,
    PENDING
}

/**
 * @dev EIP-712 utility functions for primitives
 */
library PrimitivesEip712 {
    // computes the hash of an array of tss keys
    function eip712hash(TssKey memory tssKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("TssKey(uint8 yParity,uint256 xCoord)"), tssKey.yParity, tssKey.xCoord));
    }

    // computes the hash of an array of tss keys
    function eip712hash(TssKey[] memory tssKeys) internal pure returns (bytes32) {
        bytes memory keysHashed = new bytes(tssKeys.length * 32);
        uint256 ptr;
        assembly {
            ptr := keysHashed
        }
        for (uint256 i = 0; i < tssKeys.length; i++) {
            bytes32 hash = eip712hash(tssKeys[i]);
            assembly {
                ptr := add(ptr, 32)
                mstore(ptr, hash)
            }
        }

        return keccak256(keysHashed);
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function eip712hash(UpdateKeysMessage memory message) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("UpdateKeysMessage(TssKey[] revoke,TssKey[] register)TssKey(uint8 yParity,uint256 xCoord)"),
                eip712hash(message.revoke),
                eip712hash(message.register)
            )
        );
    }

    function eip712TypedHash(UpdateKeysMessage memory message, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32)
    {
        return _computeTypedHash(domainSeparator, eip712hash(message));
    }

    function eip712hashMem(GmpMessage memory message) internal pure returns (bytes32 id) {
        bytes memory data = message.data;
        /// @solidity memory-safe-assembly
        assembly {
            let offset := sub(message, 32)
            let backup := mload(offset)
            {
                id := keccak256(add(data, 32), mload(data))
                mstore(offset, 0xeb1e0a6b8c4db87ab3beb15e5ae24e7c880703e1b9ee466077096eaeba83623b)
                {
                    let offset2 := add(offset, 0xe0)
                    let backup2 := mload(offset2)
                    mstore(offset2, id)
                    id := keccak256(offset, 0x100)
                    mstore(offset2, backup2)
                }
            }
            mstore(offset, backup)
        }
    }

    function eip712TypedHash(GmpMessage calldata message, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32 messageHash, bytes memory r)
    {
        bytes calldata data = message.data;
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(0x40)
            // keccak256("GmpMessage(bytes32 source,uint16 srcNetwork,address dest,uint16 destNetwork,uint256 gasLimit,uint256 salt,bytes data)")
            mstore(add(r, 0x0004), 0xeb1e0a6b8c4db87ab3beb15e5ae24e7c880703e1b9ee466077096eaeba83623b)
            mstore(add(r, 0x0024), calldataload(add(message, 0x00))) // message.source
            mstore(add(r, 0x0044), calldataload(add(message, 0x20))) // message.srcNetwork
            mstore(add(r, 0x0064), calldataload(add(message, 0x40))) // message.dest
            mstore(add(r, 0x0084), calldataload(add(message, 0x60))) // message.destNetwork
            mstore(add(r, 0x00a4), calldataload(add(message, 0x80))) // message.gasLimit
            mstore(add(r, 0x00c4), calldataload(add(message, 0xa0))) // message.salt

            // Copy message.data to memory
            let size := data.length
            mstore(add(r, 0x0104), size) // message.data length
            calldatacopy(add(r, 0x0124), data.offset, size) // message.data

            // Computed GMP Typed Hash
            messageHash := keccak256(add(r, 0x0124), size) // keccak(message.data)
            mstore(add(r, 0x00e4), messageHash)
            messageHash := keccak256(add(r, 0x04), 0x0100) // GMP eip712 hash
            mstore(0, 0x1901)
            mstore(0x20, domainSeparator)
            mstore(0x40, messageHash) // this will be restored at the end of this function
            messageHash := keccak256(0x1e, 0x42) // GMP Typed Hash

            // onGmpReceived
            size := and(add(size, 31), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0)
            size := add(size, 0xa4)
            mstore(add(r, 0x0064), 0x01900937) // selector
            mstore(add(r, 0x0060), size) // length
            mstore(add(r, 0x0084), messageHash) // GMP Typed Hash
            mstore(add(r, 0x00a4), calldataload(add(message, 0x20))) // msg.network
            mstore(add(r, 0x00c4), calldataload(add(message, 0x00))) // msg.source
            mstore(add(r, 0x00e4), 0x80) // msg.data offset

            size := and(add(size, 31), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0)
            size := add(size, 0x60)
            mstore(0x40, add(add(r, size), 0x40))
            r := add(r, 0x60)
        }
    }

    function eip712TypedHashMem(GmpMessage memory message, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32 messageHash)
    {
        messageHash = eip712hashMem(message);
        messageHash = _computeTypedHash(domainSeparator, messageHash);
    }

    function _computeTypedHash(bytes32 domainSeparator, bytes32 messageHash) private pure returns (bytes32 r) {
        /// @solidity memory-safe-assembly
        assembly {
            let b2 := mload(0x40)
            {
                let b1 := mload(0x20)
                {
                    let b0 := mload(0x00)
                    {
                        mstore(0, 0x1901)
                        mstore(0x20, domainSeparator)
                        mstore(0x40, messageHash)
                        r := keccak256(0x1e, 0x42)
                    }
                    mstore(0x00, b0)
                }
                mstore(0x20, b1)
            }
            mstore(0x40, b2)
        }
    }
}
