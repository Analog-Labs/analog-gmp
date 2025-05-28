// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/storage/Routes.sol)
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {RouteStore} from "../src/storage/Routes.sol";
import {Route} from "../src/Primitives.sol";

contract RouteStoreTest is Test {
    using RouteStore for RouteStore.MainStorage;

    uint16 constant TEST_NETWORK_ID = 1;
    bytes32 constant TEST_GATEWAY = bytes32(uint256(0x1));
    uint64 constant TEST_GAS_LIMIT = 500_000;
    uint128 constant TEST_BASE_FEE = 0.01 ether;
    uint256 constant TEST_NUMERATOR = 15;
    uint256 constant TEST_DENOMINATOR = 10;

    function getStore() internal pure returns (RouteStore.MainStorage storage) {
        return RouteStore.getMainStorage();
    }

    function externalCreateRoute(Route calldata route) external {
        getStore().createOrUpdateRoute(route);
    }

    // this way we can convert from memory to calldata
    function insertRouteCall(Route memory route) internal {
        bytes memory callData = abi.encodeWithSelector(this.externalCreateRoute.selector, route);
        (bool success,) = address(this).call(callData);
        require(success, "Call failed");
    }

    function testCreateNewRoute() public {
        Route memory newRoute = Route({
            networkId: TEST_NETWORK_ID,
            gateway: TEST_GATEWAY,
            gasLimit: TEST_GAS_LIMIT,
            baseFee: TEST_BASE_FEE,
            relativeGasPriceNumerator: TEST_NUMERATOR,
            relativeGasPriceDenominator: TEST_DENOMINATOR
        });

        insertRouteCall(newRoute);

        RouteStore.NetworkInfo memory stored = getStore().get(TEST_NETWORK_ID);
        assertEq(stored.gateway, TEST_GATEWAY, "Gateway mismatch");
        assertTrue(getStore().has(TEST_NETWORK_ID), "Route not added");
    }

    function testUpdateExistingRoute() public {
        testCreateNewRoute();

        Route memory updatedRoute = Route({
            networkId: TEST_NETWORK_ID,
            gateway: TEST_GATEWAY,
            gasLimit: TEST_GAS_LIMIT * 2,
            baseFee: TEST_BASE_FEE * 2,
            relativeGasPriceNumerator: TEST_NUMERATOR * 3,
            relativeGasPriceDenominator: TEST_DENOMINATOR
        });

        vm.expectEmit(true, true, true, true);
        emit RouteStore.RouteUpdated(
            updatedRoute.networkId,
            updatedRoute.relativeGasPriceNumerator,
            updatedRoute.relativeGasPriceDenominator,
            updatedRoute.baseFee,
            updatedRoute.gasLimit
        );

        insertRouteCall(updatedRoute);

        RouteStore.NetworkInfo memory stored = getStore().get(TEST_NETWORK_ID);
        assertEq(stored.gasLimit, updatedRoute.gasLimit, "Gas limit update failed");
        assertEq(stored.baseFee, updatedRoute.baseFee, "Base fee update failed");
    }

    function testRemoveRoute() public {
        testCreateNewRoute();
        assertTrue(getStore().remove(TEST_NETWORK_ID), "Removal failed");
        assertFalse(getStore().has(TEST_NETWORK_ID), "Route still exists");
        assertEq(getStore().length(), 0, "Store length mismatch");
    }

    function testListRoutes() public {
        uint8 numRoutes = 5;
        for (uint16 i = 1; i <= numRoutes; i++) {
            Route memory r = Route({
                networkId: i,
                gateway: bytes32(uint256(i)),
                gasLimit: uint64(i) * 100_000,
                baseFee: uint128(i) * 0.01 ether,
                relativeGasPriceNumerator: i * 2,
                relativeGasPriceDenominator: i * 3
            });
            insertRouteCall(r);
        }

        Route[] memory routes = getStore().listRoutes();
        assertEq(routes.length, numRoutes, "Route count mismatch");

        for (uint16 i = 0; i < numRoutes; i++) {
            uint16 expectedId = i + 1;
            assertEq(routes[i].networkId, expectedId, "Network ID order mismatch");
            assertEq(routes[i].gasLimit, uint64(expectedId) * 100_000, "Gas limit order mismatch");
        }
    }

    function testInvalidParameters() public {
        Route memory invalidRoute = Route({
            networkId: TEST_NETWORK_ID,
            gateway: bytes32(0),
            gasLimit: TEST_GAS_LIMIT,
            baseFee: TEST_BASE_FEE,
            relativeGasPriceNumerator: TEST_NUMERATOR,
            relativeGasPriceDenominator: TEST_DENOMINATOR
        });

        vm.expectRevert(RouteStore.ZeroGatewayForNewRoute.selector);
        insertRouteCall(invalidRoute);

        testCreateNewRoute();
        Route memory invalidUpdate = Route({
            networkId: TEST_NETWORK_ID,
            gateway: TEST_GATEWAY,
            gasLimit: TEST_GAS_LIMIT,
            baseFee: TEST_BASE_FEE,
            relativeGasPriceNumerator: TEST_NUMERATOR,
            relativeGasPriceDenominator: 0
        });

        vm.expectRevert(RouteStore.InvalidRouteParameters.selector);
        insertRouteCall(invalidUpdate);
    }
}
