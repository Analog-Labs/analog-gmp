// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/interfaces/IGateway.sol)

pragma solidity >=0.8.0;

import {GmpMessage, GmpSender} from "../Primitives.sol";

/**
 * @dev Required interface of an Gateway compliant contract
 */
interface IGateway {
    /**
     * @dev New GMP submitted by calling the `submitMessage` method.
     */
    event MessageReceived(
        bytes32 indexed id,
        GmpMessage msg
    );

    function networkId() external view returns (uint16);

    /**
     * @notice Estimate the gas cost of execute a GMP message.
     * @dev This function is called on the destination chain before calling the gateway to execute a source contract.
     * @param networkid The target chain where the contract call will be made
     * @param messageSize Message size
     * @param messageSize Message gas limit
     */
    function estimateMessageCost(uint16 networkid, uint256 messageSize, uint256 gasLimit)
        external
        view
        returns (uint256);

    /**
     * @dev Send message from chain A to chain B
     * @param destinationAddress the target address on the destination chain
     * @param destinationNetwork the target chain where the contract call will be made
     * @param executionGasLimit the gas limit available for the contract call
     * @param data message data with no specified format
     */
    function submitMessage(
        address destinationAddress,
        uint16 destinationNetwork,
        uint128 executionGasLimit,
        bytes calldata data
    ) external payable returns (bytes32);
}
