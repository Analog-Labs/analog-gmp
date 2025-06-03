// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import "src/oracle/IOracle.sol";
import {Test, console} from "forge-std/Test.sol";

interface IUniswapV2Factory {
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IERC20 {
    function decimals() external view returns (uint8);
}

contract UniswapV2Oracle is IOracle {
    address public immutable factory;
    address public immutable USDT;

    constructor(address _factory, address _usdt) {
        factory = _factory;
        USDT = _usdt;
    }

    function getPrice(address token) external view returns (uint256, uint256) {
        return getTokenValueInUSDT(token, 10 ** IERC20(token).decimals());
    }

    function getTokenValueInUSDT(address token, uint256 amount) public view returns (uint256, uint256) {
        address pairAddress = IUniswapV2Factory(factory).getPair(token, USDT);
        require(pairAddress != address(0), "Pair does not exist");

        IUniswapV2Pair pair = IUniswapV2Pair(pairAddress);
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        require(reserve0 > 0 && reserve1 > 0, "Insufficient liquidity");

        (uint256 reserveToken, uint256 reserveUSDT) =
            pair.token0() == USDT ? (reserve1, reserve0) : (reserve0, reserve1);

        uint8 tokenDecimals = IERC20(token).decimals();
        uint8 usdtDecimals = IERC20(USDT).decimals(); // address token1 = pair.token1();

        // e.g. lets say we wanna get price fo 1eth
        // and pool have 10 eth and 30000 usd then
        //                1e18  * 30000USD    * 10 ** 1e18             / 10eth         * 10 ** 1e6
        uint256 price = (amount * reserveUSDT * (10 ** tokenDecimals)) / (reserveToken * (10 ** usdtDecimals));
        console.log("price: {}", price);
        console.log("reserve0: {}", reserve0);
        console.log("reserve1: {}", reserve1);

        uint256 scale = 10 ** tokenDecimals;
        uint256 integer_part = price / scale;
        uint256 fraction = price % scale;
        return (integer_part, fraction);
    }

    function getPairAddress(address tokenA, address tokenB) external view returns (address) {
        return IUniswapV2Factory(factory).getPair(tokenA, tokenB);
    }
}
