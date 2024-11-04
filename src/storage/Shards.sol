// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/EnumerableSet.sol)
pragma solidity ^0.8.20;

import {TssKey} from "../Primitives.sol";
import {EnumerableSet, Pointer} from "../utils/EnumerableSet.sol";
import {StoragePtr} from "../utils/Pointer.sol";

/**
 * @dev EIP-7201 Shard's Storage
 */
library ShardStore {
    using Pointer for StoragePtr;
    using Pointer for uint256;
    using EnumerableSet for EnumerableSet.Map;

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
     * @dev Current status of the shard
     */
    enum ShardStatus {
        Unregistered,
        Active,
        Revoked
    }

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     *
     * @custom:storage-location erc7201:analog.one.gateway.shards
     */
    struct KeyInfo {
        uint216 _gap;
        ShardStatus status;
        uint32 nonce;
    }

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     *
     * @custom:storage-location erc7201:analog.one.gateway.shards
     */
    struct MainStorage {
        EnumerableSet.Map shards;
    }

    error ShardAlreadyRegistered(ShardID id);
    error ShardNotExists(ShardID id);

    function getMainStorage() internal pure returns (MainStorage storage $) {
        assembly {
            $.slot := _EIP7201_NAMESPACE
        }
    }

    function asPtr(KeyInfo storage keyInfo) internal pure returns (StoragePtr ptr) {
        assembly {
            ptr := keyInfo.slot
        }
    }

    function _getKeyInfo(StoragePtr ptr) private pure returns (KeyInfo storage keyInfo) {
        assembly {
            keyInfo.slot := ptr
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(MainStorage storage store, KeyInfo storage keyInfo) internal view returns (bool) {
        return store.shards.contains(asPtr(keyInfo));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function exists(MainStorage storage store, ShardID id) internal view returns (bool) {
        return store.shards.exists(ShardID.unwrap(id));
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(MainStorage storage store, TssKey memory shard) internal returns (bool) {
        StoragePtr ptr = store.shards.add(bytes32(shard.xCoord));
        if (ptr.isNull()) {
            return false;
        }
        KeyInfo storage keyInfo = _getKeyInfo(ptr);
        keyInfo._gap = 0;
        keyInfo.status = ShardStatus.Active;
        keyInfo.nonce = 1;
        return true;
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(MainStorage storage store, ShardID id) internal returns (bool) {
        StoragePtr ptr = store.shards.remove(ShardID.unwrap(id));
        if (ptr.isNull()) {
            return false;
        }
        KeyInfo storage keyInfo = _getKeyInfo(ptr);
        keyInfo._gap = 0;
        keyInfo.status = ShardStatus.Revoked;
        return true;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(MainStorage storage store) private view returns (uint256) {
        return store.shards.length();
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
    function at(MainStorage storage store, uint256 index) internal view returns (KeyInfo storage) {
        StoragePtr ptr = store.shards.at(index);
        require(ptr.isNull() == false, "ShardStore: index out of bounds");
        return _getKeyInfo(ptr);
    }

    /**
     * @dev Returns the value associated with `key`. O(1).
     *
     * Requirements:
     *
     * - `key` must be in the map.
     */
    function get(MainStorage storage store, bytes32 key) internal view returns (KeyInfo storage) {
        StoragePtr ptr = store.shards.get(key);
        require(ptr.isNull() == false, "ShardStore: key not found");
        return _getKeyInfo(ptr);
    }

    //     /**
    //      * @dev Return the entire set in an array
    //      *
    //      * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
    //      * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
    //      * this function has an unbounded cost, and using it as part of a state-changing function may render the function
    //      * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
    //      */
    //     function _values(MainStorage storage store) private view returns (KeyInfo[] memory) {
    //         StoragePtr[] memory keys = store.shards;
    //         KeyInfo[] memory values = new KeyInfo[](keys.length);
    //         for (uint256 i = 0; i < keys.length; i++) {
    //             values[i] = _getKeyInfo(store.shards[keys[i]]);
    //         }
    //         return values;
    //     }
}
