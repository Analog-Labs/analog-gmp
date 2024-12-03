// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/utils/GmpProxy.sol)

pragma solidity >=0.8.0;

import {ERC1967} from "../../src/utils/ERC1967.sol";
import {IGmpReceiver} from "../../src/interfaces/IGmpReceiver.sol";
import {IGateway} from "../../src/interfaces/IGateway.sol";
import {BranchlessMath} from "../../src/utils/BranchlessMath.sol";


contract GatewayProxy is IGmpReceiver {
    using BranchlessMath for uint256;

    event MessageReceived(bytes32 indexed id, GmpMessage msg);

	struct GmpMessage {
		bytes32 foreign;
		uint16 foreign_network;
		address local;
		uint128 gasLimit;
		uint128 gasCost;
		uint64 nonce;
		bytes data;
	}

    IGateway public immutable GATEWAY;
    uint16 public immutable NETWORK_ID;

    constructor(address gateway) payable {
        GATEWAY = IGateway(gateway);
        NETWORK_ID = GATEWAY.networkId();
    }

    function sendMessage(GmpMessage calldata message) external payable {
        require(message.foreign == bytes32(uint256(uint160(address(this)))), "Invalid foreign address");
        require(message.foreign_network == NETWORK_ID, "Invalid foreign network");
        require(message.local == address(this), "Invalid local address");
        uint256 value = address(this).balance.min(msg.value);
        address destination = address(uint160(uint256(message.foreign)));
        GATEWAY.submitMessage{value: value}(destination, message.foreign_network, message.gasLimit, message.data);
    }

    function onGmpReceived(bytes32 id, uint128 network, bytes32 source, bytes calldata payload)
        external
        payable
        returns (bytes32)
    {
        GmpMessage memory message = GmpMessage({
            foreign: source,
            foreign_network: uint16(network),
            local: address(this),
            gasLimit: uint128(gasleft()),
            gasCost: uint128(tx.gasprice),
            nonce: 0,
            data: payload
        });
        emit MessageReceived(id, message);
        return id;
    }
}
