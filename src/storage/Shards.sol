// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/storage/Shards.sol)
pragma solidity ^0.8.20;

import {TssKey, Signature, PrimitiveUtils} from "../Primitives.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

/**
 * @dev EIP-7201 Shard's Storage
 */
library ShardStore {
    using EnumerableMap for EnumerableMap.UintToUintMap;
    using PrimitiveUtils for bool;

    /**
     * @dev Namespace of the shards storage `analog.one.gateway.shards`.
     * keccak256(abi.encode(uint256(keccak256("analog.one.gateway.shards")) - 1)) & ~bytes32(uint256(0xff));
     */
    bytes32 internal constant _EIP7201_NAMESPACE = 0x582bcdebbeef4fb96dde802cfe96e9942657f4bedb5cfe94e8786bb683eb1f00;

    /**
     * @dev Shard ID, this is the xCoord of the TssKey
     */
    type ShardID is bytes32;

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     *
     * @custom:storage-location erc7201:analog.one.gateway.shards
     */
    struct ShardInfo {
        uint8 yParity;
        uint32 nonce;
        uint64 createdAtBlock;
    }

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     *
     */
    struct MainStorage {
        EnumerableMap.UintToUintMap shardIds;
        mapping(uint256 => ShardInfo) shards;
    }

    error ShardAlreadyRegistered(ShardID id);
    error ShardNotExists(ShardID id);
    error IndexOutOfBounds(uint256 index);
    error InvalidYParity();
    error YParityMismatch();

    function getMainStorage() internal pure returns (MainStorage storage $) {
        assembly {
            $.slot := _EIP7201_NAMESPACE
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function has(MainStorage storage store, ShardID id) internal view returns (bool) {
        return store.shardIds.contains(uint256(ShardID.unwrap(id)));
    }

    /**
     * @dev Get or create a value. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function getOrAdd(MainStorage storage store, ShardID shardId) private returns (bool, ShardInfo storage) {
        uint256 id = uint256(ShardID.unwrap(shardId));
        bool exists = store.shardIds.contains(id);
        if (!exists) {
            store.shardIds.set(id, 1);
        }
        return (!exists, store.shards[id]);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Reverts if the value does not exist in the set.
     */
    function remove(MainStorage storage store, ShardID id) internal {
        uint256 shardId = uint256(ShardID.unwrap(id));
        bool existed = store.shardIds.remove(shardId);
        if (existed) {
            delete store.shards[shardId];
        }
        revert ShardNotExists(id);
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(MainStorage storage store) internal view returns (uint256) {
        return store.shardIds.length();
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(MainStorage storage store, uint256 index) internal view returns (ShardID, ShardInfo storage) {
        if (index >= store.shardIds.length()) {
            revert IndexOutOfBounds(index);
        }
        (uint256 key,) = store.shardIds.at(index);
        return (ShardID.wrap(bytes32(key)), store.shards[key]);
    }

    /**
     * @dev Returns the value associated with `key`. O(1).
     *
     * Requirements:
     * - `key` must be in the map.
     */
    function get(MainStorage storage store, ShardID key) internal view returns (ShardInfo storage) {
        uint256 shardId = uint256(ShardID.unwrap(key));
        if (!store.shardIds.contains(shardId)) {
            revert ShardNotExists(key);
        }
        return store.shards[shardId];
    }

    /**
     * @dev Returns the `KeyInfo` associated with `TssKey`. O(1).
     *
     * Requirements:
     * - `key.xCoord` must be in the map.
     */
    function get(MainStorage storage store, TssKey calldata key) internal view returns (ShardInfo storage) {
        return get(store, ShardID.wrap(bytes32(key.xCoord)));
    }

    /**
     * @dev Returns the `KeyInfo` associated with `Signature`. O(1).
     *
     * Requirements:
     * - `signature.xCoord` must be in the map.
     */
    function get(MainStorage storage store, Signature calldata signature) internal view returns (ShardInfo storage) {
        return get(store, ShardID.wrap(bytes32(signature.xCoord)));
    }

    /**
     * @dev Returns the value associated with `key`. O(1).
     */
    function tryGet(MainStorage storage store, ShardID key) private view returns (bool, ShardInfo storage) {
        uint256 shardId = uint256(ShardID.unwrap(key));
        bool exists = store.shardIds.contains(shardId);
        return (exists, store.shards[shardId]);
    }

    /**
     * @dev Register a single TSS key.
     * Requirements:
     * - The `newKey` should not be already registered.
     */
    function register(MainStorage storage store, TssKey calldata newKey) internal returns (bool) {
        // Check y-parity
        if (newKey.yParity != 27 && newKey.yParity != 28) {
            revert InvalidYParity();
        }

        // Read shard from storage
        ShardID id = ShardID.wrap(bytes32(newKey.xCoord));
        (bool created, ShardInfo storage stored) = getOrAdd(store, id);

        // Check if the shard is already registered
        if (!created) {
            if (stored.nonce != 1 && newKey.yParity != stored.yParity) {
                revert YParityMismatch();
            }
            return false;
        }

        // Get the current status and nonce
        ShardInfo memory shard = stored;

        if (shard.createdAtBlock != 0 && shard.yParity != newKey.yParity) {
            revert YParityMismatch();
        }

        // Update nonce
        shard.nonce |= uint32((shard.nonce == 0).toUint());

        // Save new status and nonce in the storage
        stored.createdAtBlock = (shard.createdAtBlock > 0).ternaryU64(shard.createdAtBlock, uint64(block.number));
        stored.nonce = shard.nonce;
        stored.yParity = newKey.yParity;
        return true;
    }

    /**
     * @dev Revoke Shards keys.
     * Requirements:
     * - The `keys` must be registered.
     */
    function revoke(MainStorage storage store, TssKey calldata key) internal returns (bool) {
        // Read shard from storage
        ShardID id = ShardID.wrap(bytes32(key.xCoord));
        (bool exists, ShardInfo memory stored) = tryGet(store, id);

        if (exists) {
            // Check y-parity
            if (stored.yParity != key.yParity) {
                revert YParityMismatch();
            }
            return _revoke(store, id);
        }
        return false;
    }

    /**
     * @dev Revoke Shards keys.
     */
    function _revoke(MainStorage storage store, ShardID id) public returns (bool) {
        uint256 shardId = uint256(ShardID.unwrap(id));
        bool existed = store.shardIds.remove(shardId);
        if (existed) {
            delete store.shards[shardId];
        }
        return existed;
    }

    /**
     * @dev Replace TSS keys in batch.
     * Requirements:
     * - The `keys` may or may not be registered.
     */
    function replaceTssKeys(MainStorage storage store, TssKey[] calldata keys)
        internal
        returns (TssKey[] memory created, TssKey[] memory revoked)
    {
        unchecked {
            revoked = listShards(store);
            created = new TssKey[](keys.length);

            // Make sure the tss keys are correctly ordered, this makes easier to prevent repeated keys, and
            // allows binary search.
            uint256 createdCount = 0;
            for (uint256 i = 0; i < keys.length; i++) {
                TssKey calldata key = keys[i];
                if (i > 0) {
                    TssKey calldata previousKey = keys[i - 1];
                    require(
                        previousKey.xCoord < key.xCoord, "tss keys must be orderd by 'key.xCoord' in asceding order"
                    );
                }

                if (register(store, key)) {
                    // Shard registered
                    created[createdCount++] = TssKey({yParity: key.yParity, xCoord: key.xCoord});
                } else {
                    // Shard already registered, remove it from the revoke list.
                    uint256 len = revoked.length;
                    for (uint256 j = 0; j < len; j++) {
                        TssKey memory current = revoked[j];
                        if (current.xCoord == key.xCoord) {
                            revoked[j] = revoked[len - 1];
                            len--;
                            assembly {
                                // decrement list, equivalent to `revoked.length--`
                                mstore(revoked, len)
                            }
                        }
                    }
                }
            }

            // Update `created` list length
            assembly {
                mstore(created, createdCount)
            }

            // Revoke Shards
            for (uint256 i = 0; i < revoked.length; i++) {
                TssKey memory key = revoked[i];
                _revoke(store, ShardID.wrap(bytes32(key.xCoord)));
            }
        }
    }

    /**
     * @dev Return all shards registered currently registered.
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function listShards(MainStorage storage store) internal view returns (TssKey[] memory) {
        uint256 len = store.shardIds.length();
        TssKey[] memory shards = new TssKey[](len);

        for (uint256 i = 0; i < len; i++) {
            (uint256 key,) = store.shardIds.at(i);
            ShardInfo storage shard = store.shards[key];
            shards[i] = TssKey(shard.yParity, key);
        }
        return shards;
    }
}
