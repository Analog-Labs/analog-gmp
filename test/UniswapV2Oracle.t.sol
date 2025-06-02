// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {UniswapV2Oracle} from "src/oracle/UniswapV2Oracle.sol";

contract UniswapV2OracleTest is Test {
    UniswapV2Oracle oracle;
    // IUniswapV2Factory factory;
    // IUniswapV2Pair pair;

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant FACTORY = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;

    function setUp() public {
        vm.createSelectFork({urlOrAlias: "https://eth.meowrpc.com"});
        oracle = new UniswapV2Oracle(FACTORY, WETH, USDT);
    }

    function testGetNativePrice() public view {
        uint256 price = oracle.getNativePrice();
        console.log("WETH/USDT Price:", price);
    }
}
