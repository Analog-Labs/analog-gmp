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
    address public immutable WETH;
    address public immutable USDT;

    constructor(address _factory, address _weth, address _usdt) {
        factory = _factory;
        WETH = _weth;
        USDT = _usdt;
    }

    function getNativePrice() external view override returns (uint256, uint256) {
        return getTokenPrice(WETH, USDT, 1 ether);
    }

    function getTokenPrice(address tokenA, address tokenB, uint256 amount) public view returns (uint256, uint256) {
        address pairAddress = IUniswapV2Factory(factory).getPair(tokenA, tokenB);
        console.log("pair address: ", pairAddress);
        require(pairAddress != address(0), "Pair does not exist");

        IUniswapV2Pair pair = IUniswapV2Pair(pairAddress);

        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        require(reserve0 > 0 && reserve1 > 0, "Insufficient liquidity");
        console.log("reserve0 is, ", reserve0);
        console.log("reserve1 is, ", reserve1);

        address token0 = pair.token0();
        // address token1 = pair.token1();

        uint256 reserveA;
        uint256 reserveB;

        if (tokenA == token0) {
            reserveA = uint256(reserve0);
            reserveB = uint256(reserve1);
        } else {
            reserveA = uint256(reserve1);
            reserveB = uint256(reserve0);
        }

        uint8 decimalsA = IERC20(tokenA).decimals();
        console.log("decimal a", decimalsA);
        uint8 decimalsB = IERC20(tokenB).decimals();
        console.log("decimal b", decimalsB);

        // e.g. lets say we wanna get price fo 1eth
        // and pool have 10 eth and 30000 usd then
        //                1e18  * 30000USD *  10 ** 1e18        / 10eth     *  10 ** 1e6
        uint256 price = (amount * reserveB * (10 ** decimalsA)) / (reserveA * (10 ** decimalsB));

        uint256 scale = 10 ** decimalsA;
        uint256 integer_part = price / scale;
        uint256 fraction = price % scale;
        return (integer_part, fraction);
    }

    function getPairAddress(address tokenA, address tokenB) external view returns (address) {
        return IUniswapV2Factory(factory).getPair(tokenA, tokenB);
    }
}
