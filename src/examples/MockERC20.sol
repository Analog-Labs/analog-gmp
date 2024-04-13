// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/examples/MockERC20.sol)

pragma solidity >=0.8.0;

import {ERC20} from "@solmate/tokens/ERC20.sol";
import {IGmpRecipient} from "../interfaces/IGmpRecipient.sol";

contract MockERC20 is ERC20, IGmpRecipient {
    uint8 private constant DECIMALS = 6;
    address private immutable GATEWAY;

    constructor(string memory name, string memory symbol, address gatewayAddress) ERC20(name, symbol, DECIMALS) {
        GATEWAY = gatewayAddress;
        _mint(msg.sender, 1000000000000000000000000);
    }

    function onGmpReceived(bytes32, uint128, bytes32, bytes calldata) external payable returns (bytes32) {
        require(msg.sender == GATEWAY, "MockERC20: Invalid gateway");
        return bytes32(0);
    }
}
