// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Primitives.sol)

pragma solidity >=0.8.0;

import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {UFloatMath, UFloat9x56} from "./utils/Float9x56.sol";
import {NetworkID} from "./NetworkID.sol";

/**
 * @dev Maximum size of the GMP payload
 */
uint256 constant MAX_PAYLOAD_SIZE = 0x6000;

/**
 * @dev GmpSender is the sender of a GMP message
 */
type GmpSender is bytes32;

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
    GmpSender source;
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
 * @dev Message payload used to update the network info.
 * @param networkId Domain EIP-712 - Replay Protection Mechanism.
 * @param domainSeparator Domain EIP-712 - Replay Protection Mechanism.
 * @param gasLimit The maximum amount of gas we allow on this particular network.
 * @param relativeGasPrice Gas price of destination chain, in terms of the source chain token.
 * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
 * @param mortality maximum block in which this message is valid.
 */
struct UpdateNetworkInfo {
    uint16 networkId;
    bytes32 domainSeparator;
    uint64 gasLimit;
    UFloat9x56 relativeGasPrice;
    uint128 baseFee;
    uint64 mortality;
}

/**
 * @dev A Route represents a communication channel between two networks.
 * @param networkId The id of the provided network.
 * @param gasLimit The maximum amount of gas we allow on this particular network.
 * @param gateway Destination chain gateway address.
 * @param relativeGasPriceNumerator Gas price numerator in terms of the source chain token.
 * @param relativeGasPriceDenominator Gas price denominator in terms of the source chain token.
 */
struct Route {
    NetworkID networkId;
    uint64 gasLimit;
    uint128 baseFee;
    bytes32 gateway;
    uint256 relativeGasPriceNumerator;
    uint256 relativeGasPriceDenominator;
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
    INSUFFICIENT_FUNDS,
    PENDING
}

struct GmpCallback {
    bytes32 id;
    GmpSender source;
    uint16 srcNetwork;
    address dest;
    uint16 destNetwork;
    uint256 gasLimit;
    uint256 salt;
    bytes callback;
}

// /**
//  * @dev EIP-712 utility for `GmpCallback`
//  */
// library GmpCallbackUtils {}

/**
 * @dev EIP-712 utility functions for primitives
 */
library PrimitiveUtils {
    /**
     * @dev GMP message EIP-712 Type Hash.
     * Declared as raw value to enable it to be used in inline assembly
     * keccak256("GmpMessage(bytes32 source,uint16 srcNetwork,address dest,uint16 destNetwork,uint256 gasLimit,uint256 salt,bytes data)")
     */
    bytes32 internal constant GMP_MESSAGE_TYPE_HASH = 0xeb1e0a6b8c4db87ab3beb15e5ae24e7c880703e1b9ee466077096eaeba83623b;

    function toAddress(GmpSender sender) internal pure returns (address) {
        return address(uint160(uint256(GmpSender.unwrap(sender))));
    }

    function toSender(address addr, bool isContract) internal pure returns (GmpSender) {
        uint256 sender = BranchlessMath.toUint(isContract) << 160 | uint256(uint160(addr));
        return GmpSender.wrap(bytes32(sender));
    }

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

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function eip712hash(UpdateNetworkInfo calldata message) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "UpdateNetworkInfo(uint16 networkId,bytes32 domainSeparator,uint64 gasLimit,UFloat9x56 relativeGasPrice,uint128 baseFee)"
                ),
                message.networkId,
                message.domainSeparator,
                message.gasLimit,
                message.relativeGasPrice,
                message.baseFee
            )
        );
    }

    function eip712TypedHash(UpdateNetworkInfo calldata message, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32)
    {
        return _computeTypedHash(domainSeparator, eip712hash(message));
    }

    function eip712TypedHash(UpdateKeysMessage memory message, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32)
    {
        return _computeTypedHash(domainSeparator, eip712hash(message));
    }

    function eip712hash(GmpMessage memory message) internal pure returns (bytes32 id) {
        bytes memory data = message.data;
        /// @solidity memory-safe-assembly
        assembly {
            // keccak256(message.data)
            id := keccak256(add(data, 32), mload(data))

            // now compute the GmpMessage Type Hash without memory copying
            let offset := sub(message, 32)
            let backup := mload(offset)
            {
                mstore(offset, GMP_MESSAGE_TYPE_HASH)
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

    function encodeCallback(GmpMessage calldata message, bytes32 domainSeparator)
        internal
        pure
        returns (GmpCallback memory r)
    {
        bytes calldata data = message.data;
        // /// @solidity memory-safe-assembly
        assembly {
            r := mload(0x40)

            // GmpMessage Type Hash
            mstore(add(r, 0x0000), GMP_MESSAGE_TYPE_HASH)
            mstore(add(r, 0x0020), calldataload(add(message, 0x00))) // message.source
            mstore(add(r, 0x0040), calldataload(add(message, 0x20))) // message.srcNetwork
            mstore(add(r, 0x0060), calldataload(add(message, 0x40))) // message.dest
            mstore(add(r, 0x0080), calldataload(add(message, 0x60))) // message.destNetwork
            mstore(add(r, 0x00a0), calldataload(add(message, 0x80))) // message.gasLimit
            mstore(add(r, 0x00c0), calldataload(add(message, 0xa0))) // message.salt

            // Copy message.data to memory
            let size := data.length
            mstore(add(r, 0x01c4), size) // message.data.length
            calldatacopy(add(r, 0x01e4), data.offset, size) // message.data

            // Computed GMP Typed Hash
            let messageHash := keccak256(add(r, 0x01e4), size) // keccak(message.data)
            mstore(add(r, 0x00e0), messageHash)
            messageHash := keccak256(r, 0x0100) // GMP eip712 hash
            mstore(0, 0x1901)
            mstore(0x20, domainSeparator)
            mstore(0x40, messageHash) // this will be restored at the end of this function
            messageHash := keccak256(0x1e, 0x42) // GMP Typed Hash

            // Retore message.data.offset
            mstore(add(r, 0x00e0), add(r, 0x0120))
            mstore(r, messageHash)

            // selector + GMP_ID + network + source + data.offset + data.length
            size := add(and(add(size, 31), 0xffffffe0), 0xa4)

            // onGmpReceived(bytes32 id, uint128 network, bytes32 source, bytes calldata payload)
            mstore(add(r, 0x0124), 0x01900937) // selector
            mstore(add(r, 0x0120), size) // length
            mstore(add(r, 0x0144), messageHash) // id
            mstore(add(r, 0x0164), calldataload(add(message, 0x20))) // network
            mstore(add(r, 0x0184), calldataload(add(message, 0x00))) // source
            mstore(add(r, 0x01a4), 0x80) // payload.offset

            // update free memory pointer
            size := add(and(add(size, 31), 0xffffffe0), 0x0120)
            size := and(add(add(r, size), 31), 0xffffffe0)
            mstore(0x40, add(size, 0x40))
        }
    }

    function eip712TypedHash(GmpMessage memory message, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32 messageHash)
    {
        messageHash = eip712hash(message);
        messageHash = _computeTypedHash(domainSeparator, messageHash);
    }

    function _computeTypedHash(bytes32 domainSeparator, bytes32 messageHash) private pure returns (bytes32 r) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0, 0x1901000000000000000000000000000000000000000000000000000000000000)
            mstore(0x02, domainSeparator)
            mstore(0x22, messageHash)
            r := keccak256(0, 0x42)
            mstore(0x22, 0)
        }
    }
}
