// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/utils/GmpProxy.sol)

pragma solidity >=0.8.0;

import {ERC1967} from "../../src/utils/ERC1967.sol";
import {IGmpReceiver} from "../../src/interfaces/IGmpReceiver.sol";
import {IGateway} from "../../src/interfaces/IGateway.sol";
import {BranchlessMath} from "../../src/utils/BranchlessMath.sol";

contract GmpProxy is IGmpReceiver {
    using BranchlessMath for uint256;

    event MessageReceived(bytes32 indexed id, GmpMessage msg);

    struct GmpMessage {
        uint16 srcNetwork;
        uint16 destNetwork;
        bytes32 src;
        bytes32 dest;
        uint64 nonce;
        uint128 gasLimit;
        uint128 gasCost;
        bytes data;
    }

    IGateway public immutable GATEWAY;
    uint16 public immutable NETWORK_ID;

    constructor(address gateway) payable {
        GATEWAY = IGateway(gateway);
        NETWORK_ID = GATEWAY.networkId();
    }

    function sendMessage(GmpMessage calldata message) external payable {
        uint256 value = address(this).balance.min(msg.value);
        address destination = address(uint160(uint256(message.dest)));
        GATEWAY.submitMessage{value: value}(destination, message.destNetwork, message.gasLimit, message.data);
    }

    function estimateMessageCost(uint256 messageSize, uint256 gasLimit) external view returns (uint256) {
        return GATEWAY.estimateMessageCost(NETWORK_ID, messageSize, gasLimit);
    }

    function onGmpReceived(bytes32 id, uint128, bytes32, bytes calldata payload) external payable returns (bytes32) {
        // For testing purpose
        // we keep the original struct in payload so we dont depend on OnGmpReceived call since it doesnt provide everything.
        (
            uint16 srcNetwork,
            uint16 destNetwork,
            bytes32 src,
            bytes32 dest,
            uint64 nonce,
            uint128 gasLimit,
            uint128 gasCost,
            bytes memory data
        ) = abi.decode(payload, (uint16, uint16, bytes32, bytes32, uint64, uint128, uint128, bytes));

        GmpMessage memory message = GmpMessage({
            srcNetwork: srcNetwork,
            destNetwork: destNetwork,
            src: src,
            dest: dest,
            nonce: nonce,
            gasLimit: gasLimit,
            gasCost: gasCost,
            data: data
        });
        message.data = payload;

        emit MessageReceived(id, message);
        return id;
    }
}
