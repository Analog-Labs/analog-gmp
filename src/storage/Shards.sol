// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/utils/EnumerableSet.sol)
pragma solidity ^0.8.20;

import {TssKey} from "../Primitives.sol";
// import {EnumerableSet} from "../utils/EnumerableSet.sol";

/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```solidity
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * As of v3.3.0, sets of type `bytes32` (`Bytes32Set`), `address` (`AddressSet`)
 * and `uint256` (`UintSet`) are supported.
 *
 * [WARNING]
 * ====
 * Trying to delete such a structure from storage will likely result in data corruption, rendering the structure
 * unusable.
 * See https://github.com/ethereum/solidity/pull/11843[ethereum/solidity#11843] for more info.
 *
 * In order to clean an EnumerableSet, you can either remove all elements one by one or create a fresh instance using an
 * array of EnumerableSet.
 * ====
 */
library ShardsStorage {
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
        uint64 index;
        ShardStatus status;
        uint32 nonce;
        uint152 _gap;
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
        ShardID[] keys;
        mapping(ShardID => KeyInfo) shards;
    }

    error ShardAlreadyRegistered(ShardID id);
    error ShardNotExists(ShardID id);

    bytes32 internal constant _SHARDS =
        keccak256(abi.encode(uint256(keccak256("analog.one.gateway.shards")) - 1)) & ~bytes32(uint256(0xff));

    function _getMainStorage() internal pure returns (MainStorage storage $) {
        assembly {
            $.slot := _EIP7201_NAMESPACE
        }
    }

    // /**
    //  * @dev Derive an ERC-7201 slot from a string (namespace).
    //  */
    // function erc7201Slot(string memory namespace) internal pure returns (bytes32 slot) {
    //     assembly ("memory-safe") {
    //         mstore(0x00, sub(keccak256(add(namespace, 0x20), mload(namespace)), 1))
    //         slot := and(keccak256(0x00, 0x20), not(0xff))
    //     }
    // }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _exists(KeyInfo storage keyInfo) private view returns (bool r) {
        assembly {
            r := gt(sload(keyInfo.slot), 0)
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(MainStorage storage s, ShardID id) private view returns (bool) {
        return _exists(s.shards[id]);
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(MainStorage storage s, TssKey memory shard) private returns (bool) {
        ShardID id = ShardID.wrap(bytes32(shard.xCoord));
        KeyInfo storage keyInfo = s.shards[id];
        if (_exists(keyInfo)) {
            // revert ShardAlreadyRegistered(id);
            return false;
        }
        keyInfo.index = uint64(s.keys.length);
        keyInfo.status = ShardStatus.Active;
        keyInfo.nonce = 1;
        s.keys.push(id);
        return true;
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(MainStorage storage s, ShardID id) private returns (bool) {
        unchecked {
            // We cache the value's position to prevent multiple reads from the same storage slot
            ShardID[] storage keys = s.keys;
            uint256 size = keys.length;
            uint256 index = s.shards[id].index;
            if (index > 0 && index < type(uint64).max && size > 0) {
                if (index < size) {
                    ShardID lastKey = keys[size - 1];
                    // Move the lastValue to the index where the value to delete is
                    keys[index - 1] = lastKey;
                    // Update the tracked position of the lastValue (that was just moved)
                    s.shards[lastKey].index = uint64(index);
                }
                keys.pop();
                delete s.shards[id];
                return true;
            }
            return false;
        }
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(MainStorage storage s) private view returns (uint256) {
        return s.keys.length;
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
    function _at(MainStorage storage s, uint256 index) private view returns (KeyInfo storage) {
        return s.shards[s.keys[index]];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(MainStorage storage s) private view returns (KeyInfo[] memory) {
        ShardID[] memory keys = s.keys;
        KeyInfo[] memory values = new KeyInfo[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            values[i] = s.shards[keys[i]];
        }
        return values;
    }
}
