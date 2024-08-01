// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import {Schnorr} from "@frost-evm/Schnorr.sol";
import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {GasUtils} from "./utils/GasUtils.sol";
import {ERC1967} from "./utils/ERC1967.sol";
import {UFloat9x56, UFloatMath} from "./utils/Float9x56.sol";
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
    GmpStatus,
    GmpSender,
    PrimitiveUtils
} from "./Primitives.sol";

abstract contract GatewayEIP712 {
    // EIP-712: Typed structured data hashing and signing
    // https://eips.ethereum.org/EIPS/eip-712
    uint16 internal immutable NETWORK_ID;
    address internal immutable PROXY_ADDRESS;
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor(uint16 networkId, address gateway) {
        NETWORK_ID = networkId;
        PROXY_ADDRESS = gateway;
        DOMAIN_SEPARATOR = computeDomainSeparator(networkId, gateway);
    }

    // Computes the EIP-712 domain separador
    function computeDomainSeparator(uint256 networkId, address addr) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Analog Gateway Contract"),
                keccak256("0.1.0"),
                uint256(networkId),
                address(addr)
            )
        );
    }
}

contract Gateway is IGateway, IExecutor, IUpgradable, GatewayEIP712 {
    using PrimitiveUtils for UpdateKeysMessage;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for address;
    using BranchlessMath for uint256;
    using UFloatMath for UFloat9x56;

    uint8 internal constant SHARD_ACTIVE = (1 << 0); // Shard active bitflag
    uint8 internal constant SHARD_Y_PARITY = (1 << 1); // Pubkey y parity bitflag

    /**
     * @dev Maximum size of the message payload
     */
    uint256 MAX_MESSAGE_SIZE = 0x6000;

    // Non-zero value used to initialize the `prevMessageHash` storage
    bytes32 internal constant FIRST_MESSAGE_PLACEHOLDER = bytes32(uint256(2 ** 256 - 1));

    // Shard data, maps the pubkey coordX (which is already collision resistant) to shard info.
    mapping(bytes32 => KeyInfo) _shards;

    // GMP message status
    mapping(bytes32 => GmpInfo) _messages;

    // Source address => Source network => Deposit Amount
    mapping(GmpSender => mapping(uint16 => uint256)) _deposits;

    // Network ID => Source network
    // deprecated: _networkInfo
    mapping(uint16 => bytes32) _networks;

    // Hash of the previous GMP message submitted.
    bytes32 public prevMessageHash;

    // Replay protection mechanism, stores the hash of the executed messages
    // messageHash => shardId
    mapping(bytes32 => bytes32) _executedMessages;

    // Network ID => Source network
    mapping(uint16 => NetworkInfo) _networkInfo;

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     */
    struct KeyInfo {
        uint216 _gap; // gap, so we can use later for store more information about a shard
        uint8 status; // 0 = unregisted, 1 = active, 2 = revoked
        uint32 nonce; // shard nonce
    }

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

    /**
     * @dev Network info stored in the Gateway Contract
     */
    struct NetworkInfo {
        bytes32 domainSeparator; // domain EIP-712 - Replay Protection Mechanism.
        /// @dev The maximum amount of gas we allow on this particular network.
        uint64 gasLimit;
        /// @dev Gas price of destination chain, in terms of the source chain token.
        UFloat9x56 relativeGasPrice;
        /// @dev base fee for cross-chain message approval on destination, in terms of source native gas token.
        uint128 baseFee;
    }

    constructor(uint16 network, address proxy) payable GatewayEIP712(network, proxy) {}

    // EIP-712 typed hash
    function initialize(address admin, TssKey[] memory keys, Network[] calldata networks) external {
        require(PROXY_ADDRESS == address(this), "only proxy can be initialize");
        require(prevMessageHash == 0, "already initialized");
        ERC1967.setAdmin(admin);

        // Initialize the prevMessageHash with a non-zero value to avoid the first GMP to spent more gas,
        // once initialize the storage cost 21k gas, while alter it cost just 2800 gas.
        prevMessageHash = FIRST_MESSAGE_PLACEHOLDER;

        // Register networks
        _updateNetworks(networks);

        // Register keys
        _registerKeys(keys);

        // emit event
        TssKey[] memory revoked = new TssKey[](0);
        emit KeySetChanged(bytes32(0), revoked, keys);
    }

    function gmpInfo(bytes32 id) external view returns (GmpInfo memory) {
        return _messages[id];
    }

    function depositOf(GmpSender source, uint16 network) external view returns (uint256) {
        return _deposits[source][network];
    }

    function keyInfo(bytes32 id) external view returns (KeyInfo memory) {
        return _shards[id];
    }

    function networkId() external view returns (uint16) {
        return NETWORK_ID;
    }

    /**
     * @dev  Verify if shard exists, if the TSS signature is valid then increment shard's nonce.
     */
    function _verifySignature(Signature calldata signature, bytes32 message) private view {
        // Load shard from storage
        KeyInfo storage signer = _shards[bytes32(signature.xCoord)];

        // Verify if shard is active
        uint8 status = signer.status;
        require((status & SHARD_ACTIVE) > 0, "shard key revoked or not exists");

        // Load y parity bit, it must be 27 (even), or 28 (odd)
        // ref: https://ethereum.github.io/yellowpaper/paper.pdf
        uint8 yParity = uint8(BranchlessMath.select((status & SHARD_Y_PARITY) > 0, 28, 27));

        // Verify Signature
        require(
            Schnorr.verify(yParity, signature.xCoord, uint256(message), signature.e, signature.s),
            "invalid tss signature"
        );
    }

    // Converts a `TssKey` into an `KeyInfo` unique identifier
    function _tssKeyToShardId(TssKey memory tssKey) private pure returns (bytes32) {
        // The tssKey coord x is already collision resistant
        // if we are unsure about it, we can hash the coord and parity bit
        return bytes32(tssKey.xCoord);
    }

    // Converts a `TssKey` into an `KeyInfo` unique identifier
    function _updateNetworks(Network[] calldata networks) private {
        for (uint256 i = 0; i < networks.length; i++) {
            Network calldata network = networks[i];
            bytes32 domainSeparator = computeDomainSeparator(network.id, network.gateway);
            _networks[network.id] = domainSeparator;
            NetworkInfo storage info = _networkInfo[network.id];
            info.domainSeparator = domainSeparator;
            info.gasLimit = 15_000_000; // Default to 15M gas
            info.relativeGasPrice = UFloatMath.ONE;
            info.baseFee = 0;
        }
    }

    function _registerKeys(TssKey[] memory keys) private {
        // We don't perform any arithmetic operation, except iterate a loop
        unchecked {
            // Register or activate tss key (revoked keys keep the previous nonce)
            for (uint256 i = 0; i < keys.length; i++) {
                TssKey memory newKey = keys[i];

                // Read shard from storage
                bytes32 shardId = _tssKeyToShardId(newKey);
                KeyInfo storage shard = _shards[shardId];
                uint8 status = shard.status;
                uint32 nonce = shard.nonce;

                // Check if the shard is not active
                require((status & SHARD_ACTIVE) == 0, "already active, cannot register again");

                // Check y-parity
                uint8 yParity = newKey.yParity;
                require(yParity == (yParity & 1), "y parity bit must be 0 or 1, cannot register shard");

                // If nonce is zero, it's a new shard.
                // If the shard exists, the provided y-parity must match the original one
                uint8 actualYParity = uint8(BranchlessMath.toUint((status & SHARD_Y_PARITY) > 0));
                require(
                    nonce == 0 || actualYParity == yParity,
                    "the provided y-parity doesn't match the existing y-parity, cannot register shard"
                );

                // if is a new shard shard, set its initial nonce to 1
                shard.nonce = uint32(BranchlessMath.select(nonce == 0, 1, nonce));

                // enable/disable the y-parity flag
                status = uint8(BranchlessMath.select(yParity > 0, status | SHARD_Y_PARITY, status & ~SHARD_Y_PARITY));

                // enable SHARD_ACTIVE bitflag
                status |= SHARD_ACTIVE;

                // Save new status in the storage
                shard.status = status;
            }
        }
    }

    function _revokeKeys(TssKey[] memory keys) private {
        // We don't perform any arithmetic operation, except iterate a loop
        unchecked {
            // Revoke tss keys
            for (uint256 i = 0; i < keys.length; i++) {
                TssKey memory revokedKey = keys[i];

                // Read shard from storage
                bytes32 shardId = _tssKeyToShardId(revokedKey);
                KeyInfo storage shard = _shards[shardId];

                // Check if the shard exists and is active
                require(shard.nonce > 0, "shard doesn't exists, cannot revoke key");
                require((shard.status & SHARD_ACTIVE) > 0, "cannot revoke a shard key already revoked");

                // Check y-parity
                {
                    uint8 yParity = (shard.status & SHARD_Y_PARITY) > 0 ? 1 : 0;
                    require(yParity == revokedKey.yParity, "invalid y parity bit, cannot revoke key");
                }

                // Disable SHARD_ACTIVE bitflag
                shard.status = shard.status & (~SHARD_ACTIVE); // Disable active flag
            }
        }
    }

    // Register/Revoke TSS keys and emits [`KeySetChanged`] event
    function _updateKeys(bytes32 messageHash, TssKey[] memory keysToRevoke, TssKey[] memory newKeys) private {
        // We don't perform any arithmetic operation, except iterate a loop
        unchecked {
            // Revoke tss keys (revoked keys can be registred again keeping the previous nonce)
            _revokeKeys(keysToRevoke);

            // Register or activate revoked keys
            _registerKeys(newKeys);
        }
        emit KeySetChanged(messageHash, keysToRevoke, newKeys);
    }

    // Register/Revoke TSS keys using shard TSS signature
    function updateKeys(Signature calldata signature, UpdateKeysMessage memory message) public {
        bytes32 messageHash = message.eip712TypedHash(DOMAIN_SEPARATOR);

        // Verify signature and if the message was already executed
        require(_executedMessages[messageHash] == bytes32(0), "message already executed");
        _verifySignature(signature, messageHash);

        // Store the message hash to prevent replay attacks
        _executedMessages[messageHash] = bytes32(signature.xCoord);

        // Register/Revoke shards pubkeys
        _updateKeys(messageHash, message.revoke, message.register);
    }

    // Deposit balance to refund callers of execute
    function deposit(GmpSender source, uint16 network) public payable {
        // Check if the source network is supported
        require(_networks[network] != bytes32(0), "unsupported network");
        _deposits[source][network] += msg.value;
    }

    function _gmpInsufficientFunds(bytes32 payloadHash, GmpMessage calldata message)
        private
        returns (GmpStatus status, bytes32 result)
    {
        // Verify if this GMP message was already executed
        GmpInfo storage gmp = _messages[payloadHash];
        require(gmp.status == GmpStatus.NOT_FOUND, "message already executed");

        // Set status and result
        status = GmpStatus.INSUFFICIENT_FUNDS;
        result = bytes32(0);

        // Store gmp execution status on storage
        gmp.status = status;
        gmp.blockNumber = uint64(block.number);

        // Emit event
        emit GmpExecuted(payloadHash, message.source, message.dest, status, result);
    }

    // Execute GMP message
    function _execute(bytes32 payloadHash, GmpMessage calldata message, bytes memory data)
        private
        returns (GmpStatus status, bytes32 result)
    {
        // Verify if this GMP message was already executed
        GmpInfo storage gmp = _messages[payloadHash];
        require(gmp.status == GmpStatus.NOT_FOUND, "message already executed");

        // Update status to `pending` to prevent reentrancy attacks.
        gmp.status = GmpStatus.PENDING;
        gmp.blockNumber = uint64(block.number);

        // Cap the GMP gas limit to 80% of the block gas limit
        // OBS: we assume the remaining 20% is enough for the Gateway execution, which is a safe assumption
        // once most EVM blockchains have gas limits above 10M and don't need more than 60k gas for the Gateway execution.
        uint256 maxGasLimit = block.gaslimit >> 1; // 50% of the block gas limit
        uint256 gasLimit = BranchlessMath.min(message.gasLimit, maxGasLimit);

        // Execute GMP call
        bool success;
        address dest = message.dest;

        /// @solidity memory-safe-assembly
        assembly {
            // Using low-level assembly because the GMP is considered executed
            // regardless if the call reverts or not.
            let ptr := add(data, 32)
            let size := mload(data)
            mstore(data, 0)

            // returns 1 if the call succeed, and 0 if it reverted
            success :=
                call(
                    gasLimit, // call gas limit (defined in the GMP message)
                    dest, // dest address
                    0, // value in wei to transfer (always zero for GMP)
                    ptr, // input memory pointer
                    size, // input size
                    data, // output memory pointer
                    32 // output size (fixed 32 bytes)
                )

            // Get Result, reuse data to keep a predictable memory expansion
            result := mload(data)
            mstore(data, size)
        }

        // Update GMP status
        status = GmpStatus(BranchlessMath.select(success, uint256(GmpStatus.SUCCESS), uint256(GmpStatus.REVERT)));

        // Persist gmp execution status on storage
        gmp.status = status;

        // Emit event
        emit GmpExecuted(payloadHash, message.source, message.dest, status, result);
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
        // Theoretically we could remove the destination network field
        // and fill it up with the network id of the contract, then the signature will fail.
        require(message.destNetwork == NETWORK_ID, "invalid gmp network");
        require(_networks[message.srcNetwork] != bytes32(0), "source network no supported");

        // Verify the signature
        (bytes32 messageHash, bytes memory data) = message.encodeCallback(DOMAIN_SEPARATOR);
        _verifySignature(signature, messageHash);

        // Compute the GMP execution gas cost
        (uint256 baseCost, uint256 executionCost) = GasUtils.executionGasCost(message.data.length);
        uint256 gasUsed = gasleft();

        // Check if the source has enough deposit and if the caller provided
        // enough gas to execute the GMP message
        uint256 deposited = _deposits[message.source][message.srcNetwork];
        unchecked {
            // Cap the GMP gas limit to 50% of the block gas limit
            uint256 gasLimit = block.gaslimit >> 1; // 50% of the block gas limit
            gasLimit = BranchlessMath.min(message.gasLimit, gasLimit);

            // Check if the source has enough deposit before executing the GMP message
            uint256 minDeposit = baseCost.saturatingAdd(executionCost).saturatingAdd(gasLimit);
            if (deposited < minDeposit.saturatingMul(tx.gasprice)) {
                return _gmpInsufficientFunds(messageHash, message);
            }

            // Check if the relayer provided enough gas to execute the GMP message
            // uint256 minGasLeft = gasLimit.saturatingAdd(39190);
            uint256 minGasLeft = gasLimit.saturatingAdd(39117);
            require(gasUsed >= minGasLeft, "insufficient gas to execute GMP message");

            // Add base cost to the gas used
            gasUsed = minDeposit;
        }

        (status, result) = _execute(messageHash, message, data);

        // Calculate a gas refund, capped to protect against huge spikes in `tx.gasprice`
        // that could drain funds unnecessarily. During these spikes, relayers should back off.
        unchecked {
            uint256 refund = BranchlessMath.min(gasUsed * tx.gasprice, deposited);
            _deposits[message.source][message.srcNetwork] -= refund;
            payable(msg.sender).transfer(refund);
        }
    }

    function getNetwork(uint16 id) public view returns (bytes32) {
        return _networks[id];
    }

    // function setFee(uint16 id, UFloat9x56 relativeGasPrice) external {
    //     _networks[id].relativeGasPrice = relativeGasPrice;
    // }

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
        bytes memory data
    ) external payable returns (bytes32) {
        // Check if the message data is too large
        require(data.length < 0x6000, "msg data too large");

        // Check if the destination network is supported
        NetworkInfo storage info = _networkInfo[destinationNetwork];
        bytes32 domainSeparator = info.domainSeparator;
        require(domainSeparator != bytes32(0), "unsupported network");

        // Check if the source has enough deposit to execute the GMP message
        {
            (uint256 baseGas, uint256 executionGas) = GasUtils.executionGasCost(data.length);
            uint256 gasPrice = uint256(info.baseFee) + info.relativeGasPrice.mul(baseGas + executionGas);
            require(msg.value >= gasPrice, "insufficient deposit");
        }

        // We use 20 bytes for represent the address and 1 bit for the contract flag
        GmpSender source = msg.sender.toSender(tx.origin != msg.sender);

        // Salt is equal to the previous message id (EIP-712 hash), this allows us to establish a sequence and eaily query the message history.
        bytes32 prevHash = prevMessageHash;

        // if the messageHash is the first message, we use a zero salt
        uint256 salt = BranchlessMath.select(prevHash == FIRST_MESSAGE_PLACEHOLDER, 0, uint256(prevHash));

        // Create GMP message and update prevMessageHash
        GmpMessage memory message =
            GmpMessage(source, NETWORK_ID, destinationAddress, destinationNetwork, executionGasLimit, salt, data);
        prevHash = message.eip712TypedHash(domainSeparator);
        prevMessageHash = prevHash;

        emit GmpCreated(
            prevHash, GmpSender.unwrap(source), destinationAddress, destinationNetwork, executionGasLimit, salt, data
        );
        return prevHash;
    }

    function estimateMessageCost(uint16 networkid, uint256 messageSize) external view returns (uint256) {
        if (messageSize > MAX_MESSAGE_SIZE) {
            return 2 ** 256 - 1;
        }
        NetworkInfo storage network = _networkInfo[networkid];
        uint256 baseFee = uint256(network.baseFee);
        UFloat9x56 relativeGasPrice = _networkInfo[networkid].relativeGasPrice;
        require(baseFee > 0 || UFloat9x56.unwrap(relativeGasPrice) > 0);
        (uint256 baseGas, uint256 executionGas) = GasUtils.executionGasCost(messageSize);
        return relativeGasPrice.mul(baseGas + executionGas) + baseFee;
    }

    /*//////////////////////////////////////////////////////////////
                               ADMIN LOGIC
    //////////////////////////////////////////////////////////////*/

    function _getAdmin() private view returns (address admin) {
        admin = ERC1967.getAdmin();
        // If the admin slot is empty, then the 0xd4833be6144AF48d4B09E5Ce41f826eEcb7706D6 is the admin
        admin = BranchlessMath.select(admin == address(0x0), 0xd4833be6144AF48d4B09E5Ce41f826eEcb7706D6, admin);
    }

    function setAdmin(address newAdmin) external payable {
        require(msg.sender == _getAdmin(), "unauthorized");
        ERC1967.setAdmin(newAdmin);
    }

    // OBS: remove != revoke (when revoked, you cannot register again)
    function sudoRemoveShards(TssKey[] memory shards) external payable {
        require(msg.sender == _getAdmin(), "unauthorized");
        for (uint256 i; i < shards.length; i++) {
            bytes32 shardId = _tssKeyToShardId(shards[i]);
            delete _shards[shardId];
        }
    }

    function sudoAddShards(TssKey[] memory shards) external payable {
        require(msg.sender == _getAdmin(), "unauthorized");
        _registerKeys(shards);
    }

    // DANGER: This function is for migration purposes only, it allows the admin to set any storage slot.
    function sudoSetStorage(uint256[2][] calldata values) external payable {
        require(msg.sender == _getAdmin(), "unauthorized");
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
        require(msg.sender == _getAdmin(), "unauthorized");

        // Store the address of the implementation contract
        ERC1967.setImplementation(newImplementation);
    }

    function upgradeAndCall(address newImplementation, bytes memory initializer)
        external
        payable
        returns (bytes memory returndata)
    {
        require(msg.sender == _getAdmin(), "unauthorized");

        // Store the address of the implementation contract
        ERC1967.setImplementation(newImplementation);

        // Initialize storage by calling the implementation's using `delegatecall`.
        bool success;
        (success, returndata) = newImplementation.delegatecall(initializer);

        // Revert if the initialization failed
        if (!success) {
            /// @solidity memory-safe-assembly
            assembly {
                revert(add(returndata, 32), mload(returndata))
            }
        }
    }
}
