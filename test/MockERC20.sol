// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/MockERC20.sol)

pragma solidity >=0.8.0;

import {ERC20} from "@solmate/tokens/ERC20.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";

contract MockERC20 is ERC20, IGmpReceiver {
    IGateway private immutable _gateway;
    MockERC20 private immutable _recipientErc20;
    uint16 private immutable _recipientNetwork;

    // Gas limit used to execute `onGmpReceived` method.
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
        MockERC20 recipient,
        uint16 recipientNetwork,
        address holder,
        uint256 initialSupply
    ) ERC20(name, symbol, 10) {
        _gateway = gatewayAddress;
        _recipientErc20 = recipient;
        _recipientNetwork = recipientNetwork;
        if (initialSupply > 0) {
            _mint(holder, initialSupply);
        }
    }

    function teleport(address to, uint256 amount) external returns (bytes32) {
        _burn(msg.sender, amount);
        bytes memory message = abi.encode(CrossChainTransfer({from: msg.sender, to: to, amount: amount}));
        return _gateway.submitMessage(address(_recipientErc20), _recipientNetwork, MSG_GAS_LIMIT, message);
    }

    function onGmpReceived(bytes32 id, uint128 network, bytes32 sender, bytes calldata data)
        external
        payable
        returns (bytes32)
    {
        require(msg.sender == address(_gateway), "Unauthorized: only the gateway can call this method");
        require(network == _recipientNetwork, "Unauthorized network");
        require(address(uint160(uint256(sender))) == address(_recipientErc20), "Unauthorized sender");
        CrossChainTransfer memory message = abi.decode(data, (CrossChainTransfer));
        _mint(message.to, message.amount);
        return id;
    }
}
