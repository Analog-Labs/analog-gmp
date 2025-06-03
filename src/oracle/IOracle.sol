// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

interface IOracle {
    function getPrice(address token) external view returns (uint256, uint256);
}
