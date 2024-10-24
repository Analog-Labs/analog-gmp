// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (scripts/Upgrade.sol)

pragma solidity ^0.8.0;

import {BranchlessMath} from "./utils/BranchlessMath.sol";

type NetworkID is uint16;

library NetworkIDHelpers {
    NetworkID internal constant MAINNET = NetworkID.wrap(0);
    NetworkID internal constant ASTAR = NetworkID.wrap(1);
    NetworkID internal constant POLYGON_POS = NetworkID.wrap(2);
    NetworkID internal constant ETHEREUM_LOCAL_DEV = NetworkID.wrap(3);
    NetworkID internal constant GOERLI = NetworkID.wrap(4);
    NetworkID internal constant SEPOLIA = NetworkID.wrap(5);
    NetworkID internal constant ASTAR_LOCAL_DEV = NetworkID.wrap(6);
    NetworkID internal constant SHIBUYA = NetworkID.wrap(7);
    NetworkID internal constant BINANCE_SMART_CHAIN_TESTNET = NetworkID.wrap(9);
    NetworkID internal constant ARBITRUM_SEPOLIA = NetworkID.wrap(10);

    function asUint(NetworkID networkId) internal pure returns (uint16) {
        return NetworkID.unwrap(networkId);
    }

    function chainId(NetworkID networkId) internal pure returns (uint64) {
        uint256 id = NetworkID.unwrap(networkId);
        uint256 chainid = type(uint256).max;

        // Ethereum Mainnet
        chainid = BranchlessMath.ternary(id == asUint(MAINNET), 0, chainid);
        // Astar
        chainid = BranchlessMath.ternary(id == asUint(ASTAR), 592, chainid);
        // Polygon PoS
        chainid = BranchlessMath.ternary(id == asUint(POLYGON_POS), 137, chainid);
        // Ethereum local testnet
        chainid = BranchlessMath.ternary(id == asUint(ETHEREUM_LOCAL_DEV), 1337, chainid);
        // Goerli
        chainid = BranchlessMath.ternary(id == asUint(GOERLI), 5, chainid);
        // Sepolia
        chainid = BranchlessMath.ternary(id == asUint(SEPOLIA), 11155111, chainid);
        // Astar local testnet
        chainid = BranchlessMath.ternary(id == asUint(ASTAR_LOCAL_DEV), 592, chainid);
        // Shibuya
        chainid = BranchlessMath.ternary(id == asUint(SHIBUYA), 81, chainid);
        // Binance Smart Chain
        chainid = BranchlessMath.ternary(id == asUint(BINANCE_SMART_CHAIN_TESTNET), 97, chainid);
        // Arbitrum Sepolia
        chainid = BranchlessMath.ternary(id == asUint(ARBITRUM_SEPOLIA), 421614, chainid);

        require(chainid != type(uint256).max, "the provided network id doesn't exists");

        return uint64(chainid);
    }

    /**
     * @dev Try to get the network id from the chain id.
     */
    function tryFromChainID(uint256 chainid) internal pure returns (bool, NetworkID) {
        uint256 networkId = type(uint256).max;

        // Ethereum Mainnet
        networkId = BranchlessMath.ternary(chainid == 0, asUint(MAINNET), networkId);
        // Astar
        networkId = BranchlessMath.ternary(chainid == 592, asUint(ASTAR), networkId);
        // Polygon PoS
        networkId = BranchlessMath.ternary(chainid == 137, asUint(POLYGON_POS), networkId);
        // Ethereum local testnet
        networkId = BranchlessMath.ternary(chainid == 1337, asUint(ETHEREUM_LOCAL_DEV), networkId);
        // Goerli
        networkId = BranchlessMath.ternary(chainid == 5, asUint(GOERLI), networkId);
        // Sepolia
        networkId = BranchlessMath.ternary(chainid == 11155111, asUint(SEPOLIA), networkId);
        // Astar local testnet
        networkId = BranchlessMath.ternary(chainid == 592, asUint(ASTAR_LOCAL_DEV), networkId);
        // Shibuya
        networkId = BranchlessMath.ternary(chainid == 81, asUint(SHIBUYA), networkId);
        // Binance Smart Chain
        networkId = BranchlessMath.ternary(chainid == 97, asUint(BINANCE_SMART_CHAIN_TESTNET), networkId);
        // Arbitrum Sepolia
        networkId = BranchlessMath.ternary(chainid == 421614, asUint(ARBITRUM_SEPOLIA), networkId);

        bool exists = networkId != type(uint256).max;
        return (exists, NetworkID.wrap(uint16(networkId)));
    }

    function fromChainID(uint256 chainid) internal pure returns (NetworkID) {
        (bool exists, NetworkID networkId) = tryFromChainID(chainid);
        require(exists, "network id doesn't exists for the given chain id");
        return networkId;
    }
}
