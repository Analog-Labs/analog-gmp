// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import {Hashing} from "./utils/Hashing.sol";
import {Schnorr} from "../lib/frost-evm/sol/Schnorr.sol";
import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {GasUtils} from "./GasUtils.sol";
import {RouteStore} from "./storage/Routes.sol";
import {ShardStore} from "./storage/Shards.sol";
import {IGateway} from "./interfaces/IGateway.sol";
import {IGmpReceiver} from "./interfaces/IGmpReceiver.sol";
import {
    Command,
    Batch,
    GatewayOp,
    GmpCallback,
    GmpMessage,
    GmpStatus,
    Route,
    PrimitiveUtils,
    Signature,
    TssKey,
    MAX_PAYLOAD_SIZE
} from "./Primitives.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Gateway is IGateway, UUPSUpgradeable, OwnableUpgradeable {
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for GmpCallback;
    using PrimitiveUtils for address;
    using BranchlessMath for uint256;
    using ShardStore for ShardStore.MainStorage;
    using RouteStore for RouteStore.MainStorage;
    using RouteStore for RouteStore.NetworkInfo;

    /**
     * @dev Emitted when a Batch is executed.
     * @param batch batch_id which is executed
     */
    event BatchExecuted(uint64 batch);

    /**
     * @dev Emitted when `GmpMessage` is executed.
     * @param id EIP-712 hash of the `GmpPayload`, which is it's unique identifier
     * @param source sender pubkey/address (the format depends on src chain)
     * @param dest recipient address
     * @param status GMP message execution status
     * @param result GMP result
     */
    event GmpExecuted(
        bytes32 indexed id, bytes32 indexed source, address indexed dest, GmpStatus status, bytes32 result
    );

    /**
     * @dev Emitted when shards are registered.
     * @param keys registered shard's keys
     */
    event ShardsRegistered(TssKey[] keys);

    /**
     * @dev Emitted when shards are unregistered.
     * @param keys unregistered shard's keys
     */
    event ShardsUnregistered(TssKey[] keys);

    // GMP message status
    mapping(bytes32 => GmpStatus) public messages;

    // Address nonce
    mapping(address => uint64) public nonces;

    bytes32 private constant GATEWAY_STORAGE_SLOT = keccak256("analog.gateway.storage");

    struct GatewayConfig {
        uint16 networkId;
    }

    function _getGatewayConfig() internal pure returns (GatewayConfig storage gs) {
        bytes32 slot = GATEWAY_STORAGE_SLOT;
        assembly {
            gs.slot := slot
        }
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(uint16 _networkId) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();

        GatewayConfig storage gs = _getGatewayConfig();
        gs.networkId = _networkId;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function admin() external view returns (address) {
        return owner();
    }

    function setAdmin(address newAdmin) external payable onlyOwner {
        transferOwnership(newAdmin);
    }

    /**
     * Withdraw funds from the gateway contract
     * @param amount The amount to withdraw
     * @param recipient The recipient address
     * @param data The data to send to the recipient (in case it is a contract)
     */
    function withdraw(uint256 amount, address recipient, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory output)
    {
        // Check if the recipient is a contract
        if (recipient.code.length > 0) {
            bool success;
            (success, output) = recipient.call{value: amount, gas: gasleft()}(data);
            if (!success) {
                assembly ("memory-safe") {
                    revert(add(output, 32), mload(output))
                }
            }
        } else {
            payable(recipient).transfer(amount);
            output = "";
        }
    }

    /**
     * @dev List all shards.
     */
    function shards() external view returns (TssKey[] memory) {
        return ShardStore.getMainStorage().listShards();
    }

    /**
     * @dev Register Shards in batch.
     */
    function setShards(TssKey[] calldata publicKeys) external onlyOwner {
        (TssKey[] memory created, TssKey[] memory revoked) = ShardStore.getMainStorage().replaceTssKeys(publicKeys);

        if (created.length > 0) {
            emit ShardsRegistered(created);
        }

        if (revoked.length > 0) {
            emit ShardsUnregistered(revoked);
        }
    }

    /**
     * @dev List all routes.
     */
    function routes() external view returns (Route[] memory) {
        return RouteStore.getMainStorage().listRoutes();
    }

    /**
     * @dev Create or update a single route
     */
    function setRoute(Route calldata info) external onlyOwner {
        RouteStore.getMainStorage().createOrUpdateRoute(info);
    }

    // IGateway implementation

    function networkId() external view returns (uint16) {
        return _getGatewayConfig().networkId;
    }

    /**
     * @notice Estimate the gas cost of execute a GMP message.
     * @dev This function is called on the destination chain before calling the gateway to execute a source contract.
     * @param network The target chain where the contract call will be made
     * @param messageSize Message size
     * @param messageSize Message gas limit
     */
    function estimateMessageCost(uint16 network, uint64 messageSize, uint64 gasLimit) external view returns (uint256) {
        RouteStore.NetworkInfo memory route = RouteStore.getMainStorage().get(network);

        // Estimate the cost
        return route.estimateWeiCost(uint16(messageSize), gasLimit);
    }

    /**
     * @dev Send message from this chain to another chain.
     * @param destinationAddress the target address on the destination chain
     * @param network the target chain where the contract call will be made
     * @param executionGasLimit the gas limit available for the contract call
     * @param data message data with no specified format
     */
    function submitMessage(address destinationAddress, uint16 network, uint64 executionGasLimit, bytes calldata data)
        external
        payable
        returns (bytes32)
    {
        // Check if the message data is too large
        require(data.length <= MAX_PAYLOAD_SIZE, "msg data is too big");

        // Check if the provided parameters are valid
        // See `RouteStorage.estimateWeiCost` at `storage/Routes.sol` for more details.
        RouteStore.NetworkInfo memory route = RouteStore.getMainStorage().get(network);
        (uint256 gasCost, uint256 fee) = route.estimateCost(data, executionGasLimit);
        require(msg.value >= fee, "insufficient tx value");

        // We use 20 bytes for represent the address and 1 bit for the contract flag
        bytes32 source = msg.sender.toSender();

        unchecked {
            // Nonce is per sender, it's incremented for every message sent.
            uint64 nextNonce = uint64(nonces[msg.sender]++);

            // Create GMP message and update nonce
            GmpMessage memory message = GmpMessage(
                source, _getGatewayConfig().networkId, destinationAddress, network, executionGasLimit, nextNonce, data
            );

            bytes32 messageId = message.messageId();
            emit GmpCreated(
                messageId,
                source,
                destinationAddress,
                network,
                executionGasLimit,
                uint64(gasCost),
                nextNonce,
                message.data
            );
            return messageId;
        }
    }

    // execute

    /**
     * @dev Lookup table to find the function pointer for a given command.
     * Different than nested if-else, this has constant gas cost regardless the number of commands.
     *
     * Obs: supports up to 16 commands.
     * See: `_buildCommandsLUT` and `_cmdTableLookup` methods for more details.
     */
    type CommandsLookUpTable is uint256;

    /**
     * @dev Dispatch a single GMP message.
     */
    function _gmpCommand(bytes calldata params) private returns (bytes32 operationHash) {
        require(params.length >= 256, "invalid GmpMessage");
        GmpMessage calldata gmp;
        assembly {
            gmp := add(params.offset, 0x20)
        }

        // Theoretically we could remove the destination network field
        // and fill it up with the network id of the contract, then the signature will fail.
        require(gmp.destNetwork == _getGatewayConfig().networkId, "invalid gmp network");

        // Check if the message data is too large
        require(gmp.data.length <= MAX_PAYLOAD_SIZE, "msg data too large");

        // Convert the `GmpMessage` into `GmpCallback`, which is a more efficient representation.
        // see `src/Primitives.sol` for more details.
        GmpCallback memory callback = gmp.toCallback();
        operationHash = callback.opHash;

        // Verify if this GMP message was already executed
        bytes32 msgId = callback.messageId();
        require(messages[msgId] == GmpStatus.NOT_FOUND, "message already executed");

        // Update status to `pending` to prevent reentrancy attacks.
        messages[msgId] = GmpStatus.PENDING;

        // Cap the GMP gas limit to 50% of the block gas limit
        // OBS: we assume the remaining 50% is enough for the Gateway execution, which is a safe assumption
        // once most EVM blockchains have gas limits above 10M and don't need more than 60k gas for the Gateway execution.
        uint256 gasLimit = BranchlessMath.min(callback.gasLimit, block.gaslimit >> 1);
        unchecked {
            // Add `all but one 64th` to the gas needed, as the defined by EIP-150
            // https://eips.ethereum.org/EIPS/eip-150
            uint256 gasNeeded = gasLimit.saturatingMul(64).saturatingDiv(63);
            // to guarantee it was provided enough gas to execute the GMP message
            gasNeeded = gasNeeded.saturatingAdd(10000);
            require(gasleft() >= gasNeeded, "insufficient gas to execute GMP message");
        }

        // Execute GMP call
        bool success;
        bytes32 result;
        {
            address dest = callback.dest;
            bytes memory onGmpReceivedCallback = callback.callback;
            assembly ("memory-safe") {
                // Using low-level assembly because the GMP is considered executed
                // regardless if the call reverts or not.
                mstore(0, 0)
                success :=
                    call(
                        gasLimit, // call gas limit defined in the GMP message or 50% of the block gas limit
                        dest, // dest address
                        0, // value in wei to transfer (always zero for GMP)
                        add(onGmpReceivedCallback, 32), // input memory pointer
                        mload(onGmpReceivedCallback), // input size
                        0, // output memory pointer
                        32 // output size (fixed 32 bytes)
                    )

                // Get Result, reuse data to keep a predictable memory expansion
                result := mload(0)
            }
        }

        // Update GMP status
        GmpStatus status =
            GmpStatus(BranchlessMath.ternary(success, uint256(GmpStatus.SUCCESS), uint256(GmpStatus.REVERT)));

        // Persist gmp execution status on storage
        messages[msgId] = status;

        // Emit event
        emit GmpExecuted(msgId, callback.source, callback.dest, status, result);
    }

    /**
     * @dev Register a single shard and returns the GatewayOp hash.
     */
    function _registerShardCommand(bytes calldata params) private returns (bytes32 operationHash) {
        require(params.length == 64, "invalid TssKey");
        TssKey calldata publicKey;
        assembly {
            publicKey := params.offset
        }
        operationHash = Hashing.hash(publicKey.yParity, publicKey.xCoord);

        bool isSuccess = ShardStore.getMainStorage().register(publicKey);
        if (isSuccess) {
            TssKey[] memory keys = new TssKey[](1);
            keys[0] = publicKey;
            emit ShardsRegistered(keys);
        }
    }

    /**
     * @dev Removes a single shard from the set.
     */
    function _unregisterShardCommand(bytes calldata params) private returns (bytes32 operationHash) {
        require(params.length == 64, "invalid TssKey");
        TssKey calldata publicKey;
        assembly {
            publicKey := params.offset
        }
        operationHash = Hashing.hash(publicKey.yParity, publicKey.xCoord);

        bool isSuccess = ShardStore.getMainStorage().revoke(publicKey);
        if (isSuccess) {
            TssKey[] memory keys = new TssKey[](1);
            keys[0] = publicKey;
            emit ShardsUnregistered(keys);
        }
    }

    /**
     * Cast the command function into a uint256.
     */
    function fnToPtr(function(bytes calldata) internal returns (bytes32) fn) private pure returns (uint256 ptr) {
        assembly {
            ptr := fn
        }
    }

    /**
     * @dev Creates a lookup table to find the function pointer for a given command.
     *
     * Motivation: More efficient than nested if-else, and also guarantees a constant gas overhead for any command, which
     * makes easier to estimate the gas cost necessary to execute the whole batch.
     */
    function _buildCommandsLUT() private pure returns (CommandsLookUpTable) {
        uint256 lookupTable;
        // GMP
        lookupTable = fnToPtr(_gmpCommand) << (uint256(Command.GMP) << 4);
        // RegisterShard
        lookupTable |= fnToPtr(_registerShardCommand) << (uint256(Command.RegisterShard) << 4);
        // UnregisterShard
        lookupTable |= fnToPtr(_unregisterShardCommand) << (uint256(Command.UnregisterShard) << 4);
        return CommandsLookUpTable.wrap(lookupTable);
    }

    /**
     * @dev Get in constant gas the function pointer for the provided command.
     * See `_buildCommandsLUT` for more details.
     */
    function _cmdTableLookup(CommandsLookUpTable lut, Command command)
        private
        pure
        returns (function(bytes calldata) internal returns (bytes32) fn)
    {
        unchecked {
            // Extract the function pointer from the table using the `Command` as index.
            uint256 ptr = CommandsLookUpTable.unwrap(lut) >> (uint256(command) << 4);
            ptr &= 0xffff;

            // Make sure the function pointer is within the code bounds.
            uint256 codeSize;
            assembly {
                codeSize := codesize()
            }
            require(ptr > 0 && ptr < codeSize, "invalid command");

            // Converts the `uint256` back to `function(bytes calldata) internal returns (bytes32) fn`
            assembly {
                fn := ptr
            }
        }
    }

    /**
     * @dev Execute a batch of `GatewayOp` and returns the maximum amount of memory used in bytes and the operations root hash.
     *
     * This method also reuses the same memory space for each command, to prevent the memory to grow and
     * increase the cost exponentially.
     * @return (uint256, bytes32) Returns a tuple containing the maximum amount of memory used in bytes and the operations root hash.
     */
    function _executeCommands(GatewayOp[] calldata operations) private returns (uint256, bytes32) {
        // Track the free memory pointer, to reset the memory after each command executed.
        uint256 freeMemPointer = GasUtils.readAllocatedMemory();
        uint256 maxAllocatedMemory = freeMemPointer;

        // Create the Command LookUp Table
        CommandsLookUpTable lut = _buildCommandsLUT();

        bytes32 operationsRootHash = bytes32(0);
        for (uint256 i = 0; i < operations.length; i++) {
            GatewayOp calldata operation = operations[i];

            // Lookup the command function pointer
            function(bytes calldata) internal returns (bytes32) commandFN = _cmdTableLookup(lut, operation.command);

            // Execute the command
            bytes32 operationHash = commandFN(operation.params);

            // Update the operations root hash
            operationsRootHash =
                Hashing.hash(uint256(operationsRootHash), uint256(operation.command), uint256(operationHash));

            // Restore the memory, to prevent the memory expansion costs to increase exponentially.
            uint256 newFreeMemPointer = GasUtils.unsafeReplaceAllocatedMemory(freeMemPointer);

            // Update the Max Allocated Memory
            maxAllocatedMemory = maxAllocatedMemory.max(newFreeMemPointer);
        }

        // Compute what was the maximum amount of memory used in bytes
        maxAllocatedMemory = maxAllocatedMemory - freeMemPointer;

        return (maxAllocatedMemory, operationsRootHash);
    }

    /**
     * @dev Verify and dispatch messages from the Timechain.
     */
    function execute(Signature calldata signature, Batch calldata batch) external {
        uint256 initialGas = gasleft();
        // Add the solidity selector overhead to the initial gas, this way we guarantee that
        // the `initialGas` represents the actual gas that was available to this contract.
        initialGas = initialGas.saturatingAdd(GasUtils.EXECUTION_SELECTOR_OVERHEAD);

        // Execute the commands and compute the operations root hash
        (, bytes32 rootHash) = _executeCommands(batch.ops);
        emit BatchExecuted(batch.batchId);

        // Compute the Batch signing hash
        rootHash = Hashing.hash(batch.version, batch.batchId, uint256(rootHash));
        bytes32 signingHash = keccak256(
            abi.encodePacked(
                "Analog GMP v2", _getGatewayConfig().networkId, bytes32(uint256(uint160(address(this)))), rootHash
            )
        );

        // Load shard from storage
        ShardStore.ShardInfo storage signer = ShardStore.getMainStorage().get(signature);

        // Verify Signature
        require(
            Schnorr.verify(signer.yParity, signature.xCoord, uint256(signingHash), signature.e, signature.s),
            "invalid tss signature"
        );

        // Refund the chronicle gas
        unchecked {
            // Extra gas overhead used to execute the refund logic.
            uint256 gasUsed = 7188;

            // Compute the gas used + base cost + proxy overhead
            gasUsed = gasUsed.saturatingAdd(GasUtils.txBaseCost());
            gasUsed = gasUsed.saturatingAdd(GasUtils.proxyOverheadGasCost(uint16(msg.data.length), 0));
            gasUsed = gasUsed.saturatingAdd(initialGas - gasleft());

            // Compute refund amount
            uint256 refund = BranchlessMath.min(gasUsed.saturatingMul(tx.gasprice), address(this).balance);

            // Refund the gas used
            assembly ("memory-safe") {
                pop(call(gas(), caller(), refund, 0, 0, 0, 0))
            }
        }
    }
}
