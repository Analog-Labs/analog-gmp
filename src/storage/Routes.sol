// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/storage/Routes.sol)
pragma solidity ^0.8.20;

import {Signature, Route, MAX_PAYLOAD_SIZE} from "../Primitives.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {BranchlessMath} from "../utils/BranchlessMath.sol";
import {StoragePtr} from "../utils/Pointer.sol";
import {GasUtils} from "../GasUtils.sol";

/**
 * @dev EIP-7201 Route's Storage
 */
library RouteStore {
    using EnumerableMap for EnumerableMap.UintToUintMap;
    using BranchlessMath for uint256;

    /**
     * @dev Namespace of the routes storage `analog.one.gateway.routes`.
     * keccak256(abi.encode(uint256(keccak256("analog.one.gateway.routes")) - 1)) & ~bytes32(uint256(0xff));
     */
    bytes32 internal constant _EIP7201_NAMESPACE = 0xb184f2aad520cf7f1f1270909517c75ae33cdf2bd7d32b997a96577f11a48800;

    /**
     * @dev Network info stored in the Gateway Contract
     * @param gasLimit The maximum amount of gas we allow on this particular network.
     * @param relativeGasPriceNumerator Gas price of destination chain, in terms of the source chain token.
     * @param relativeGasPriceDenominator Gas price of destination chain, in terms of the source chain token.
     * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
     */
    struct NetworkInfo {
        bytes32 gateway;
        uint64 gasLimit;
        uint128 baseFee;
        uint256 relativeGasPriceNumerator;
        uint256 relativeGasPriceDenominator;
        uint256 gasCoef0;
        uint256 gasCoef1;
    }

    /**
     * @dev Emitted when a route is updated.
     * @param networkId Network identifier.
     * @param relativeGasPriceNumerator Gas price of destination chain, in terms of the source chain token.
     * @param relativeGasPriceDenominator Gas price of destination chain, in terms of the source chain token.
     * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
     * @param gasLimit The maximum amount of gas we allow on this particular network.
     * @param gasCoef0.
     * @param gasCoef1.
     */
    event RouteUpdated(
        uint16 indexed networkId,
        uint256 relativeGasPriceNumerator,
        uint256 relativeGasPriceDenominator,
        uint128 baseFee,
        uint64 gasLimit,
        uint256 gasCoef0,
        uint256 gasCoef1
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
        EnumerableMap.UintToUintMap routeIds;
        mapping(uint16 => NetworkInfo) routes;
    }

    error RouteNotExists(uint16 id);
    error IndexOutOfBounds(uint256 index);
    error ZeroGatewayForNewRoute();
    error InvalidRouteParameters();

    function getMainStorage() internal pure returns (MainStorage storage $) {
        assembly {
            $.slot := _EIP7201_NAMESPACE
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function has(MainStorage storage store, uint16 networkId) internal view returns (bool) {
        return store.routeIds.contains(uint256(networkId));
    }

    /**
     * @dev Get or create a value. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function getOrAdd(MainStorage storage store, uint16 networkId) private returns (bool, NetworkInfo storage) {
        bool exists = store.routeIds.contains(uint256(networkId));
        if (!exists) {
            store.routeIds.set(uint256(networkId), 1);
        }
        return (!exists, store.routes[networkId]);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(MainStorage storage store, uint16 id) internal returns (bool) {
        bool existed = store.routeIds.remove(uint256(id));
        if (existed) {
            delete store.routes[id];
        }
        return existed;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(MainStorage storage store) internal view returns (uint256) {
        return store.routeIds.length();
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
    function at(MainStorage storage store, uint256 index) internal view returns (uint16, NetworkInfo storage) {
        if (index >= store.routeIds.length()) {
            revert IndexOutOfBounds(index);
        }
        (uint256 key,) = store.routeIds.at(index);
        uint16 networkId = uint16(key);
        return (networkId, store.routes[networkId]);
    }

    /**
     * @dev Returns the value associated with `NetworkInfo`. O(1).
     *
     * Requirements:
     * - `NetworkInfo` must be in the map.
     */
    function get(MainStorage storage store, uint16 id) internal view returns (NetworkInfo storage) {
        if (!store.routeIds.contains(uint256(id))) {
            revert RouteNotExists(id);
        }
        return store.routes[id];
    }

    function createOrUpdateRoute(MainStorage storage store, Route calldata route) internal {
        (bool created, NetworkInfo storage stored) = getOrAdd(store, route.networkId);
        if (created) {
            if (route.gateway == bytes32(0)) revert ZeroGatewayForNewRoute();
            stored.gateway = route.gateway;
        }

        if (route.relativeGasPriceDenominator == 0 && route.relativeGasPriceNumerator > 0) {
            revert InvalidRouteParameters();
        }

        // Update gas limit if it's not zero
        if (route.gasLimit > 0) stored.gasLimit = route.gasLimit;

        // Update relative gas price and base fee if any of them are greater than zero
        if (route.relativeGasPriceDenominator > 0) {
            stored.relativeGasPriceNumerator = route.relativeGasPriceNumerator;
            stored.relativeGasPriceDenominator = route.relativeGasPriceDenominator;
            stored.baseFee = route.baseFee;
            stored.gasCoef0 = route.gasCoef0;
            stored.gasCoef1 = route.gasCoef1;
        }

        emit RouteUpdated(
            route.networkId,
            stored.relativeGasPriceNumerator,
            stored.relativeGasPriceDenominator,
            stored.baseFee,
            stored.gasLimit,
            stored.gasCoef0,
            stored.gasCoef1
        );
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
        uint256 len = store.routeIds.length();
        Route[] memory routes = new Route[](len);

        for (uint256 i = 0; i < len; i++) {
            (uint256 key,) = store.routeIds.at(i);
            uint16 networkId = uint16(key);
            NetworkInfo storage route = store.routes[networkId];

            routes[i] = Route({
                networkId: networkId,
                gasLimit: route.gasLimit,
                baseFee: route.baseFee,
                gateway: route.gateway,
                relativeGasPriceNumerator: route.relativeGasPriceNumerator,
                relativeGasPriceDenominator: route.relativeGasPriceDenominator,
                gasCoef0: route.gasCoef0,
                gasCoef1: route.gasCoef1
            });
        }
        return routes;
    }

    function estimateGas(NetworkInfo memory route, uint16 messageSize, uint64 gasLimit)
        internal
        pure
        returns (uint256)
    {
        // Verify if the gas limit and message size are within the limits
        require(gasLimit <= route.gasLimit, "gas limit exceeded");
        require(messageSize <= MAX_PAYLOAD_SIZE, "maximum payload size exceeded");
        return uint256(messageSize) * route.gasCoef1 + route.gasCoef0 + gasLimit;
    }

    function estimateCost(NetworkInfo memory route, uint256 gas) internal pure returns (uint256) {
        require(route.relativeGasPriceDenominator > 0, "route is temporarily disabled");
        return gas * route.relativeGasPriceNumerator / route.relativeGasPriceDenominator + route.baseFee;
    }
}
