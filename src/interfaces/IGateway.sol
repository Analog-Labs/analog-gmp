// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/interfaces/IGateway.sol)

pragma solidity >=0.8.0;

import {GmpSender} from "../Primitives.sol";

/**
 * @dev Required interface of an Gateway compliant contract
 */
interface IGateway {
    /**
     * @dev New GMP submitted by calling the `submitMessage` method.
     * @param id EIP-712 hash of the `GmpPayload`, which is it's unique identifier
     * @param source sender account, with an extra flag indicating if it is a contract or an EOA
     * @param destinationAddress the target address on the destination chain.
     * @param destinationNetwork the target chain where the contract call will be made.
     * @param executionGasLimit the gas limit available for the contract call
     * @param salt salt is equal to the previous message id (EIP-712 hash).
     * @param data message data with no specified format
     */
    event GmpCreated(
        bytes32 indexed id,
        bytes32 indexed source,
        address indexed destinationAddress,
        uint16 destinationNetwork,
        uint256 executionGasLimit,
        uint256 salt,
        bytes data
    );

    function networkId() external view returns (uint16);

    /**
     * @notice Pay for gas of contract execution on destination chain.
     * @dev This function is called on the destination chain before calling the gateway to execute a source contract.
     * @param sender The address making the payment
     * @param sourceNetwork The target chain where the contract call will be made
     */
    function deposit(GmpSender sender, uint16 sourceNetwork) external payable;

    /**
     * @notice Pay for gas of contract execution on destination chain.
     * @dev This function is called on the destination chain before calling the gateway to execute a source contract.
     * @param sender The address making the payment
     * @param sourceNetwork The target chain where the contract call will be made
     */
    function depositOf(GmpSender sender, uint16 sourceNetwork) external view returns (uint256);

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
        uint256 executionGasLimit,
        bytes calldata data
    ) external payable returns (bytes32);
}
