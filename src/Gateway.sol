// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import {Schnorr} from "./utils/Schnorr.sol";
import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {GasUtils} from "./utils/GasUtils.sol";
import {ERC1967} from "./utils/ERC1967.sol";
import {UFloat9x56, UFloatMath} from "./utils/Float9x56.sol";
import {RouteStore} from "./storage/Routes.sol";
import {ShardStore} from "./storage/Shards.sol";
import {IGateway} from "./interfaces/IGateway.sol";
import {IUpgradable} from "./interfaces/IUpgradable.sol";
import {IGmpReceiver} from "./interfaces/IGmpReceiver.sol";
import {IExecutor} from "./interfaces/IExecutor.sol";
import {
    TssKey,
    GmpMessage,
    UpdateKeysMessage,
    Signature,
    Network,
    Route,
    GmpStatus,
    GmpSender,
    GmpCallback,
    PrimitiveUtils,
    MAX_PAYLOAD_SIZE
} from "./Primitives.sol";
import {NetworkID, NetworkIDHelpers} from "./NetworkID.sol";

abstract contract GatewayEIP712 {
    using NetworkIDHelpers for NetworkID;

    // EIP-712: Typed structured data hashing and signing
    // https://eips.ethereum.org/EIPS/eip-712
    uint16 internal immutable NETWORK_ID;
    address internal immutable PROXY_ADDRESS;

    constructor(uint16 networkId, address gateway) {
        NETWORK_ID = networkId;
        PROXY_ADDRESS = gateway;
    }
}

contract Gateway is IGateway, IExecutor, IUpgradable, GatewayEIP712 {
    using PrimitiveUtils for UpdateKeysMessage;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for address;
    using BranchlessMath for uint256;
    using UFloatMath for UFloat9x56;
    using ShardStore for ShardStore.MainStorage;
    using RouteStore for RouteStore.MainStorage;
    using RouteStore for RouteStore.NetworkInfo;
    using NetworkIDHelpers for NetworkID;

    /**
     * @dev Selector of `GmpCreated` event.
     * keccak256("GmpCreated(bytes32,bytes32,address,uint16,uint256,uint256,bytes)");
     */
    bytes32 private constant GMP_CREATED_EVENT_SELECTOR =
        0x0114885f90b5168242aa31b7afb9c2e9f88e90ce329c893d3e6c56021c4c03a5;

    /**
     * @dev The address of the `UniversalFactory` contract, must be the same on all networks.
     */
    address internal constant FACTORY = 0x0000000000001C4Bf962dF86e38F0c10c7972C6E;

    // GMP message status
    mapping(bytes32 => GmpInfo) private _messages;

    // Hash of the previous GMP message submitted.
    mapping(address => uint256) private _nonces;

    // Replay protection mechanism, stores the hash of the executed messages
    // messageHash => shardId
    mapping(bytes32 => bytes32) private _executedMessages;

    /**
     * @dev GMP info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the attributes 256 bit aligned, ex: nonce, block and status can be read in one storage access.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     */
    struct GmpInfo {
        GmpStatus status;
        uint64 blockNumber; // block in which the message was processed
    }

    constructor(uint16 network, address proxy) payable GatewayEIP712(network, proxy) {}

    // EIP-712 typed hash
    function initialize(address proxyAdmin, TssKey[] calldata keys, Network[] calldata networks) external {
        require(PROXY_ADDRESS == address(this) || msg.sender == FACTORY, "only proxy can be initialize");
        ERC1967.setAdmin(proxyAdmin);

        // Register networks
        RouteStore.getMainStorage().initialize(networks, NetworkID.wrap(NETWORK_ID));

        // Register keys
        ShardStore.getMainStorage().registerTssKeys(keys);

        // emit event
        TssKey[] memory revoked = new TssKey[](0);
        emit KeySetChanged(bytes32(0), revoked, keys);
    }

    function nonce() external view returns (uint256) {
        return _nonces[msg.sender];
    }

    function gmpInfo(bytes32 id) external view returns (GmpInfo memory) {
        return _messages[id];
    }

    function keyInfo(bytes32 id) external view returns (ShardStore.ShardInfo memory) {
        ShardStore.MainStorage storage store = ShardStore.getMainStorage();
        return store.get(ShardStore.ShardID.wrap(id));
    }

    function networkId() external view returns (uint16) {
        return NETWORK_ID;
    }

    function networkInfo(uint16 id) external view returns (RouteStore.NetworkInfo memory) {
        return RouteStore.getMainStorage().get(NetworkID.wrap(id));
    }

    /**
     * @dev  Verify if shard exists, if the TSS signature is valid then increment shard's nonce.
     */
    function _verifySignature(Signature calldata signature, bytes32 message) private view {
        // Load shard from storage
        ShardStore.ShardInfo storage signer = ShardStore.getMainStorage().get(signature);

        // Load y parity bit, it must be 27 (even), or 28 (odd)
        // ref: https://ethereum.github.io/yellowpaper/paper.pdf
        uint8 yParity = BranchlessMath.ternaryU8(signer.yParity > 0, 28, 27);

        // Verify Signature
        require(
            Schnorr.verify(yParity, signature.xCoord, uint256(message), signature.e, signature.s),
            "invalid tss signature"
        );
    }

    // Register/Revoke TSS keys using shard TSS signature
    function updateKeys(Signature calldata signature, UpdateKeysMessage calldata message) external {
        // Check if the message was already executed to prevent replay attacks
        bytes32 messageHash = message.eip712hash();
        require(_executedMessages[messageHash] == bytes32(0), "message already executed");

        // Verify the signature and store the message hash
        _verifySignature(signature, messageHash);
        _executedMessages[messageHash] = bytes32(signature.xCoord);

        // Register/Revoke shards pubkeys
        ShardStore.MainStorage storage store = ShardStore.getMainStorage();

        // Revoke tss keys (revoked keys can be registred again keeping the previous nonce)
        store.revokeKeys(message.revoke);

        // Register or activate revoked keys
        store.registerTssKeys(message.register);

        // Emit event
        emit KeySetChanged(messageHash, message.revoke, message.register);
    }

    // Execute GMP message
    function _execute(GmpCallback memory message) private returns (GmpStatus status, bytes32 result) {
        // Verify if this GMP message was already executed
        GmpInfo storage gmp = _messages[message.eip712hash];
        require(gmp.status == GmpStatus.NOT_FOUND, "message already executed");

        // Update status to `pending` to prevent reentrancy attacks.
        gmp.status = GmpStatus.PENDING;
        gmp.blockNumber = uint64(block.number);

        // Cap the GMP gas limit to 50% of the block gas limit
        // OBS: we assume the remaining 50% is enough for the Gateway execution, which is a safe assumption
        // once most EVM blockchains have gas limits above 10M and don't need more than 60k gas for the Gateway execution.
        uint256 gasLimit = BranchlessMath.min(message.gasLimit, block.gaslimit >> 1);
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
        address dest = message.dest;

        bytes memory callback = message.callback;
        assembly ("memory-safe") {
            // Using low-level assembly because the GMP is considered executed
            // regardless if the call reverts or not.
            mstore(0, 0)
            success :=
                call(
                    gasLimit, // call gas limit defined in the GMP message or 50% of the block gas limit
                    dest, // dest address
                    0, // value in wei to transfer (always zero for GMP)
                    add(callback, 32), // input memory pointer
                    mload(callback), // input size
                    0, // output memory pointer
                    32 // output size (fixed 32 bytes)
                )

            // Get Result, reuse data to keep a predictable memory expansion
            result := mload(0)
        }

        // Update GMP status
        status = GmpStatus(BranchlessMath.ternary(success, uint256(GmpStatus.SUCCESS), uint256(GmpStatus.REVERT)));

        // Persist gmp execution status on storage
        gmp.status = status;

        // Emit event
        emit GmpExecuted(message.eip712hash, message.source, message.dest, status, result);
    }

    /**
     * Execute GMP message
     * @param signature Schnorr signature
     * @param message GMP message
     */
    function execute(Signature calldata signature, GmpMessage calldata message)
        external
        returns (GmpStatus status, bytes32 result)
    {
        uint256 initialGas = gasleft();
        // Add the solidity selector overhead to the initial gas, this way we guarantee that
        // the `initialGas` represents the actual gas that was available to this contract.
        initialGas = initialGas.saturatingAdd(GasUtils.EXECUTION_SELECTOR_OVERHEAD);

        // Theoretically we could remove the destination network field
        // and fill it up with the network id of the contract, then the signature will fail.
        require(message.destNetwork == NETWORK_ID, "invalid gmp network");

        // Check if the message data is too large
        require(message.data.length <= MAX_PAYLOAD_SIZE, "msg data too large");

        // Convert the `GmpMessage` into `GmpCallback`, which is a more efficient representation.
        // see `src/Primitives.sol` for more details.
        GmpCallback memory callback = message.intoCallback();

        // Verify the TSS Schnorr Signature
        _verifySignature(signature, callback.eip712hash);

        // Execute GMP message
        (status, result) = _execute(callback);

        // Refund the chronicle gas
        unchecked {
            // Compute GMP gas used
            uint256 gasUsed = 7152;
            gasUsed = gasUsed.saturatingAdd(GasUtils.txBaseCost());
            gasUsed = gasUsed.saturatingAdd(GasUtils.proxyOverheadGasCost(uint16(msg.data.length), 64));
            gasUsed = gasUsed.saturatingAdd(initialGas - gasleft());

            // Compute refund amount
            uint256 refund = BranchlessMath.min(gasUsed.saturatingMul(tx.gasprice), address(this).balance);

            assembly ("memory-safe") {
                // Refund the gas used
                pop(call(gas(), caller(), refund, 0, 0, 0, 0))
            }
        }
    }

    /**
     * @dev Send message from this chain to another chain.
     * @param destinationAddress the target address on the destination chain
     * @param routeId the target chain where the contract call will be made
     * @param executionGasLimit the gas limit available for the contract call
     * @param data message data with no specified format
     */
    function submitMessage(address destinationAddress, uint16 routeId, uint256 executionGasLimit, bytes calldata data)
        external
        payable
        returns (bytes32)
    {
        // Check if the message data is too large
        require(data.length <= MAX_PAYLOAD_SIZE, "msg data is too big");

        // Check if the provided parameters are valid
        // See `RouteStorage.estimateWeiCost` at `storage/Routes.sol` for more details.
        RouteStore.NetworkInfo memory route = RouteStore.getMainStorage().get(NetworkID.wrap(routeId));
        require(msg.value >= route.estimateWeiCost(data, executionGasLimit), "insufficient tx value");

        // We use 20 bytes for represent the address and 1 bit for the contract flag
        GmpSender source = msg.sender.toSender(false);

        // Nonce is per sender, it's incremented for every message sent.
        uint256 nextNonce = _nonces[msg.sender]++;

        // Create GMP message and update nonce
        GmpMessage memory message =
            GmpMessage(source, NETWORK_ID, destinationAddress, routeId, executionGasLimit, nextNonce, data);

        // Emit `GmpCreated` event without copy the data, to simplify the gas estimation.
        _emitGmpCreated(
            message.eip712hash(), source, destinationAddress, routeId, executionGasLimit, nextNonce, message.data
        );
    }

    /**
     * @dev Emit `GmpCreated` event without copy the data, to simplify the gas estimation.
     */
    function _emitGmpCreated(
        bytes32 messageID,
        GmpSender source,
        address destinationAddress,
        uint16 destinationNetwork,
        uint256 executionGasLimit,
        uint256 salt,
        bytes memory payload
    ) private {
        // Emit `GmpCreated` event without copy the data, to simplify the gas estimation.
        // the assembly code below is equivalent to:
        // ```solidity
        // emit GmpCreated(prevHash, source, destinationAddress, destinationNetwork, executionGasLimit, salt, data);
        // return prevHash;
        // ```
        assembly {
            let ptr := sub(payload, 0x80)
            mstore(ptr, destinationNetwork) // dest network
            mstore(add(ptr, 0x20), executionGasLimit) // gas limit
            mstore(add(ptr, 0x40), salt) // salt
            mstore(add(ptr, 0x60), 0x80) // data offset
            let size := and(add(mload(payload), 31), 0xffffffe0)
            size := add(size, 160)
            log4(ptr, size, GMP_CREATED_EVENT_SELECTOR, messageID, source, destinationAddress)
            mstore(0, messageID)
            return(0, 32)
        }
    }

    /*//////////////////////////////////////////////////////////////
                        FEE AND PAYMENT LOGIC
    //////////////////////////////////////////////////////////////*/

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
        returns (uint256)
    {
        RouteStore.NetworkInfo memory route = RouteStore.getMainStorage().get(NetworkID.wrap(networkid));

        // Estimate the cost
        return route.estimateWeiCost(uint16(messageSize), gasLimit);
    }

    /**
     * Deposit funds to the gateway contract
     * IMPORTANT: this function must be called only by the administrator!!!!
     */
    function deposit() external payable {}

    /**
     * Withdraw funds from the gateway contract
     * @param amount The amount to withdraw
     * @param recipient The recipient address
     * @param data The data to send to the recipient (in case it is a contract)
     */
    function withdraw(uint256 amount, address recipient, bytes calldata data) external returns (bytes memory output) {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
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

    /*//////////////////////////////////////////////////////////////
                    SHARDS MANAGEMENT METHODS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev List all shards.
     */
    function shards() external view returns (TssKey[] memory) {
        return ShardStore.getMainStorage().listShards();
    }

    /**
     * @dev Returns the number of active shards.
     */
    function shardCount() external view returns (uint256) {
        return ShardStore.getMainStorage().length();
    }

    /**
     * @dev Returns a shard by index.
     * - Reverts with `IndexOutOfBounds` if the index is out of bounds.
     */
    function shardAt(uint256 index) external view returns (TssKey memory) {
        (ShardStore.ShardID xCoord, ShardStore.ShardInfo storage shard) = ShardStore.getMainStorage().at(index);
        return TssKey({xCoord: uint256(ShardStore.ShardID.unwrap(xCoord)), yParity: shard.yParity + 2});
    }

    /**
     * @dev Register a single Shards with provided TSS public key.
     */
    function setShard(TssKey calldata publicKey) external {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ShardStore.getMainStorage().register(publicKey);
    }

    /**
     * @dev Register Shards in batch.
     */
    function setShards(TssKey[] calldata publicKeys) external {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ShardStore.getMainStorage().replaceTssKeys(publicKeys);
    }

    /**
     * @dev Revoke a single shard TSS Key.
     */
    function revokeShard(TssKey calldata publicKey) external {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ShardStore.getMainStorage().revoke(publicKey);
    }

    /**
     * @dev Revoke Shards in batch.
     */
    function revokeShard(TssKey[] calldata publicKeys) external {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ShardStore.getMainStorage().revokeKeys(publicKeys);
    }

    /*//////////////////////////////////////////////////////////////
                       LISTING ROUTES AND SHARDS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev List all routes.
     */
    function routes() external view returns (Route[] memory) {
        return RouteStore.getMainStorage().listRoutes();
    }

    /**
     * @dev Create or update a single route
     */
    function setRoute(Route calldata info) external {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        RouteStore.getMainStorage().createOrUpdateRoute(info);
    }

    /**
     * @dev Create or update an array of routes
     */
    function setRoutes(Route[] calldata values) external {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        require(values.length > 0, "routes cannot be empty");
        RouteStore.MainStorage storage store = RouteStore.getMainStorage();
        for (uint256 i = 0; i < values.length; i++) {
            store.createOrUpdateRoute(values[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                               ADMIN LOGIC
    //////////////////////////////////////////////////////////////*/

    function admin() external view returns (address) {
        return ERC1967.getAdmin();
    }

    function setAdmin(address newAdmin) external payable {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ERC1967.setAdmin(newAdmin);
    }

    // OBS: remove != revoke (when revoked, you cannot register again)
    function sudoRemoveShards(TssKey[] calldata revokedKeys) external payable {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ShardStore.getMainStorage().revokeKeys(revokedKeys);
        emit KeySetChanged(bytes32(0), revokedKeys, new TssKey[](0));
    }

    function sudoAddShards(TssKey[] calldata newKeys) external payable {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        ShardStore.getMainStorage().registerTssKeys(newKeys);
        emit KeySetChanged(bytes32(0), new TssKey[](0), newKeys);
    }

    // DANGER: This function is for migration purposes only, it allows the admin to set any storage slot.
    function sudoSetStorage(uint256[2][] calldata values) external payable {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");
        require(values.length > 0, "invalid values");

        uint256 prev = 0;
        for (uint256 i = 0; i < values.length; i++) {
            uint256[2] memory entry = values[i];
            // Guarantee that the storage slot is in ascending order
            // and that there are no repeated storage slots
            uint256 key = entry[0];
            require(i == 0 || key > prev, "repeated storage slot");

            // Protect admin and implementation slots
            require(key != uint256(ERC1967.ADMIN_SLOT), "use setAdmin instead");
            require(key != uint256(ERC1967.IMPLEMENTATION_SLOT), "use upgrade instead");

            // Set storage slot
            uint256 value = entry[1];
            assembly {
                sstore(key, value)
            }
            prev = key;
        }
    }

    function upgrade(address newImplementation) external payable {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");

        // Store the address of the implementation contract
        ERC1967.setImplementation(newImplementation);
    }

    function upgradeAndCall(address newImplementation, bytes memory initializer)
        external
        payable
        returns (bytes memory returndata)
    {
        require(msg.sender == ERC1967.getAdmin(), "unauthorized");

        // Store the address of the implementation contract
        ERC1967.setImplementation(newImplementation);

        // Initialize storage by calling the implementation's using `delegatecall`.
        bool success;
        (success, returndata) = newImplementation.delegatecall(initializer);

        // Revert if the initialization failed
        if (!success) {
            assembly ("memory-safe") {
                revert(add(returndata, 32), mload(returndata))
            }
        }
    }
}
