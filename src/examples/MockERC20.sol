// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/examples/MockERC20.sol)

pragma solidity >=0.8.0;

import {ERC20} from "@solmate/tokens/ERC20.sol";
import {IGmpRecipient} from "../interfaces/IGmpRecipient.sol";
import {IGateway} from "../interfaces/IGateway.sol";

contract MockERC20 is ERC20, IGmpRecipient {
    IGateway private immutable GATEWAY;
    MockERC20 private immutable DESTINATION;
    uint16 private immutable DESTINATION_NETWORK;

    error InvalidGateway();
    error Unathorized();

    // Cross-chain transfer destination
    uint256 private constant MSG_GAS_LIMIT = 100_000;

    struct CrossChainTransfer {
        address from;
        address to;
        uint256 amount;
    }

    constructor(
        string memory name,
        string memory symbol,
        IGateway gatewayAddress,
        MockERC20 other,
        uint16 otherNetwork,
        address holder,
        uint256 initialSupply
    ) ERC20(name, symbol, 10) {
        GATEWAY = gatewayAddress;
        DESTINATION = other;
        DESTINATION_NETWORK = otherNetwork;
        if (initialSupply > 0) {
            _mint(holder, initialSupply);
        }
    }

    function teleport(address to, uint256 amount) external returns (bytes32) {
        _burn(msg.sender, amount);
        bytes memory message = abi.encode(CrossChainTransfer({from: msg.sender, to: to, amount: amount}));
        return GATEWAY.submitMessage(address(DESTINATION), 1337, MSG_GAS_LIMIT, message);
    }

    function onGmpReceived(bytes32 id, uint128 network, bytes32 sender, bytes calldata data)
        external
        payable
        returns (bytes32)
    {
        require(msg.sender == address(GATEWAY), "Invalid gateway");
        require(network == DESTINATION_NETWORK, "Invalid network");
        require(address(uint160(uint256(sender))) == address(DESTINATION), "Invalid sender");
        CrossChainTransfer memory message = abi.decode(data, (CrossChainTransfer));
        _mint(message.to, message.amount);
        return id;
    }
}
