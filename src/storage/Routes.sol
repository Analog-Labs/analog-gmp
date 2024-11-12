// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/storage/Routes.sol)
pragma solidity ^0.8.20;

import {UpdateNetworkInfo, Signature, Network} from "../Primitives.sol";
import {NetworkIDHelpers, NetworkID} from "../NetworkID.sol";
import {EnumerableSet, Pointer} from "../utils/EnumerableSet.sol";
import {BranchlessMath} from "../utils/BranchlessMath.sol";
import {UFloat9x56, UFloatMath} from "../utils/Float9x56.sol";
import {StoragePtr} from "../utils/Pointer.sol";

/**
 * @dev EIP-7201 Route's Storage
 */
library RouteStore {
    using Pointer for StoragePtr;
    using Pointer for uint256;
    using EnumerableSet for EnumerableSet.Map;
    using NetworkIDHelpers for NetworkID;
    using UFloatMath for UFloat9x56;

    /**
     * @dev Namespace of the routes storage `analog.one.gateway.routes`.
     * keccak256(abi.encode(uint256(keccak256("analog.one.gateway.routes")) - 1)) & ~bytes32(uint256(0xff));
     */
    bytes32 internal constant _EIP7201_NAMESPACE = 0xb184f2aad520cf7f1f1270909517c75ae33cdf2bd7d32b997a96577f11a48800;

    /**
     * @dev Network info stored in the Gateway Contract
     * @param domainSeparator Domain EIP-712 - Replay Protection Mechanism.
     * @param gasLimit The maximum amount of gas we allow on this particular network.
     * @param relativeGasPrice Gas price of destination chain, in terms of the source chain token.
     * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
     */
    struct NetworkInfo {
        bytes32 domainSeparator;
        uint64 gasLimit;
        UFloat9x56 relativeGasPrice;
        uint128 baseFee;
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
     * @dev Network info stored in the Gateway Contract
     * @param id Message unique id.
     * @param networkId Network identifier.
     * @param domainSeparator Domain EIP-712 - Replay Protection Mechanism.
     * @param relativeGasPrice Gas price of destination chain, in terms of the source chain token.
     * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
     * @param gasLimit The maximum amount of gas we allow on this particular network.
     */
    event NetworkUpdated(
        bytes32 indexed id,
        uint16 indexed networkId,
        bytes32 indexed domainSeparator,
        UFloat9x56 relativeGasPrice,
        uint128 baseFee,
        uint64 gasLimit
    );

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     *
     * @custom:storage-location erc7201:analog.one.gateway.routes
     */
    struct MainStorage {
        EnumerableSet.Map routes;
    }

    error ShardAlreadyRegistered(NetworkID id);
    error ShardNotExists(NetworkID id);
    error IndexOutOfBounds(uint256 index);

    function getMainStorage() internal pure returns (MainStorage storage $) {
        assembly {
            $.slot := _EIP7201_NAMESPACE
        }
    }

    /**
     * @dev Converts a `StoragePtr` into an `NetworkInfo`.
     */
    function pointerToRoute(StoragePtr ptr) private pure returns (NetworkInfo storage route) {
        assembly {
            route.slot := ptr
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function has(MainStorage storage store, NetworkID id) internal view returns (bool) {
        return store.routes.has(bytes32(uint256(id.asUint())));
    }

    /**
     * @dev Get or create a value. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function getOrAdd(MainStorage storage store, NetworkID id) private returns (bool, NetworkInfo storage) {
        (bool success, StoragePtr ptr) = store.routes.tryAdd(bytes32(uint256(id.asUint())));
        return (success, pointerToRoute(ptr));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(MainStorage storage store, NetworkID id) internal returns (bool) {
        StoragePtr ptr = store.routes.remove(bytes32(uint256(id.asUint())));
        if (ptr.isNull()) {
            return false;
        }
        return true;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(MainStorage storage store) internal view returns (uint256) {
        return store.routes.length();
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
    function at(MainStorage storage store, uint256 index) internal view returns (NetworkInfo storage) {
        StoragePtr ptr = store.routes.at(index);
        if (ptr.isNull()) {
            revert IndexOutOfBounds(index);
        }
        return pointerToRoute(ptr);
    }

    /**
     * @dev Returns the value associated with `NetworkInfo`. O(1).
     *
     * Requirements:
     * - `NetworkInfo` must be in the map.
     */
    function get(MainStorage storage store, NetworkID id) internal view returns (NetworkInfo storage) {
        StoragePtr ptr = store.routes.get(bytes32(uint256(id.asUint())));
        if (ptr.isNull()) {
            revert ShardNotExists(id);
        }
        return pointerToRoute(ptr);
    }

    /**
     * @dev Returns the value associated with `NetworkInfo`. O(1).
     */
    function tryGet(MainStorage storage store, NetworkID id) internal view returns (bool, NetworkInfo storage) {
        (bool exists, StoragePtr ptr) = store.routes.tryGet(bytes32(uint256(id.asUint())));
        return (exists, pointerToRoute(ptr));
    }

    function createOrUpdateNetworkInfo(MainStorage storage store, bytes32 messageHash, UpdateNetworkInfo calldata info)
        private
    {
        require(info.mortality >= block.number, "message expired");

        // Verify signature and if the message was already executed
        // require(_executedMessages[messageHash] == bytes32(0), "message already executed");

        // Update network info
        (bool created, NetworkInfo storage stored) = getOrAdd(store, NetworkID.wrap(info.networkId));
        require(!created || info.domainSeparator != bytes32(0), "domain separator cannot be zero");

        // Verify and update domain separator if it's not zero
        if (info.domainSeparator != bytes32(0)) {
            stored.domainSeparator = info.domainSeparator;
        }

        // Update gas limit if it's not zero
        if (info.gasLimit > 0) {
            stored.gasLimit = info.gasLimit;
        }

        // Update relative gas price and base fee if any of them are greater than zero
        if (UFloat9x56.unwrap(info.relativeGasPrice) > 0 || info.baseFee > 0) {
            stored.relativeGasPrice = info.relativeGasPrice;
            stored.baseFee = info.baseFee;
        }

        // Save the message hash to prevent replay attacks
        // _executedMessages[messageHash] = executor;

        // Update network info
        // _networkInfo[info.networkId] = stored;

        emit NetworkUpdated(
            messageHash,
            info.networkId,
            stored.domainSeparator,
            stored.relativeGasPrice,
            stored.baseFee,
            stored.gasLimit
        );
    }

    // Initialize networks
    function initialize(
        MainStorage storage store,
        Network[] calldata networks,
        NetworkID networkdID,
        function(Network calldata) internal pure returns(bytes32) computeDomainSeparator
    ) private {
        for (uint256 i = 0; i < networks.length; i++) {
            Network calldata network = networks[i];
            (bool exists, NetworkInfo storage info) = tryGet(store, NetworkID.wrap(network.id));
            require(!exists && info.domainSeparator == bytes32(0), "network already initialized");
            require(network.id != networkdID.asUint() || network.gateway == address(this), "wrong gateway address");
            info.domainSeparator = computeDomainSeparator(network);
            info.gasLimit = 15_000_000; // Default to 15M gas
            info.relativeGasPrice = UFloatMath.ONE;
            info.baseFee = 0;
        }
    }

    /**
     * @dev Return all routes registered currently registered.
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function listRoutes(MainStorage storage store) internal view returns (Route[] memory) {
        bytes32[] memory idx = store.routes.keys;
        Route[] memory routes = new Route[](idx.length);
        for (uint256 i = 0; i < idx.length; i++) {
            (bool success, NetworkInfo storage route) = tryGet(store, NetworkID.wrap(uint16(uint256(idx[i]))));
            require(success, "route not found");
            (uint256 numerator, uint256 denominator) = route.relativeGasPrice.toRational();
            routes[i] = Route({
                networkId: NetworkID.wrap(uint16(uint256(idx[i]))),
                gasLimit: route.gasLimit,
                baseFee: route.baseFee,
                gateway: route.domainSeparator,
                relativeGasPriceNumerator: numerator,
                relativeGasPriceDenominator: denominator
            });
        }
        return routes;
    }
}
