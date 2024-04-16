// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import {Schnorr} from "frost-evm/sol/Schnorr.sol";
import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {IGateway} from "./interfaces/IGateway.sol";
import {IUpgradable} from "./interfaces/IUpgradable.sol";
import {IGmpRecipient} from "./interfaces/IGmpRecipient.sol";
import {IExecutor} from "./interfaces/IExecutor.sol";
import {TssKey, GmpMessage, UpdateKeysMessage, Signature, Network, PrimitivesEip712} from "./Primitives.sol";

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
    using PrimitivesEip712 for UpdateKeysMessage;
    using PrimitivesEip712 for GmpMessage;

    uint8 internal constant GMP_STATUS_NOT_FOUND = 0; // GMP message not processed
    uint8 internal constant GMP_STATUS_SUCCESS = 1; // GMP message executed successfully
    uint8 internal constant GMP_STATUS_REVERTED = 2; // GMP message executed, but reverted
    uint8 internal constant GMP_STATUS_PENDING = 128; // GMP message is pending (used in case of reetrancy)

    uint8 internal constant SHARD_ACTIVE = (1 << 0); // Shard active bitflag
    uint8 internal constant SHARD_Y_PARITY = (1 << 1); // Pubkey y parity bitflag

    uint256 internal constant EXECUTE_GAS_DIFF = 11_325; // Measured gas cost difference for `execute`

    // Non-zero value used to initialize the `prevMessageHash` storage
    bytes32 internal constant FIRST_MESSAGE_PLACEHOLDER = bytes32(uint256(2 ** 256 - 1));

    // Shard data, maps the pubkey coordX (which is already collision resistant) to shard info.
    mapping(bytes32 => KeyInfo) _shards;

    // GMP message status
    mapping(bytes32 => GmpInfo) _messages;

    // Source address => Source network => Deposit Amount
    mapping(bytes32 => mapping(uint16 => uint256)) _deposits;

    // Source address => Source network => Deposit Amount
    mapping(uint16 => bytes32) _networks;

    // Hash of the previous GMP message submitted.
    bytes32 public prevMessageHash;

    /**
     * @dev Shard info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the shard info below 256 bit, so it can be stored in one single storage slot.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     */
    struct KeyInfo {
        uint216 _gap; // gap, so we can use later for store more information about a shard
        uint8 status; // status, 0 = unregisted, 1 = active, 3 = revoked
        uint32 nonce; // shard nonce
    }

    /**
     * @dev GMP info stored in the Gateway Contract
     * OBS: the order of the attributes matters! ethereum storage is 256bit aligned, try to keep
     * the attributes 256 bit aligned, ex: nonce, block and status can be read in one storage access.
     * reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
     */
    struct GmpInfo {
        uint184 _gap; // gap to keep status and blocknumber 256bit aligned
        uint8 status; // message status: NOT_FOUND | PENDING | SUCCESS | REVERT
        uint64 blockNumber; // block in which the message was processed
        bytes32 result; // the result of the GMP message
    }

    constructor(uint16 network, address proxy) payable GatewayEIP712(network, proxy) {}

    function initialize(TssKey[] memory keys, Network[] calldata networks) external {
        require(PROXY_ADDRESS == address(this), "only proxy can be initialize");
        require(prevMessageHash == 0, "already initialized");

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

    function depositOf(bytes32 source, uint16 network) external view returns (uint256) {
        return _deposits[source][network];
    }

    function keyInfo(bytes32 id) external view returns (KeyInfo memory) {
        return _shards[id];
    }

    function networkId() external view returns (uint16) {
        return NETWORK_ID;
    }

    // Best-effort attempt at estimating the base gas use of the transaction.
    // This includes:
    // * Cost paid for every transaction: 21000 gas
    // * Cost of calldata: Zero byte = 4 gas, Non-zero byte = 16 gas
    // * Cost of code inside submitInitial that is not metered: 14_698
    //
    // Reference: Ethereum Yellow Paper
    function _transactionBaseGas() internal pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let mask := 0x0101010101010101010101010101010101010101010101010101010101010101
            // 1
            let ptr := 0
            let v := calldataload(0)
            v := or(v, shr(4, v))
            v := or(v, shr(2, v))
            v := or(v, shr(1, v))
            v := and(v, mask)
            {
                // 2
                ptr := add(ptr, 32)
                let r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 3
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 4
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 5
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 6
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 7
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 8
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 9
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 10
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 11
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 12
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 13
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 14
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
                // 15
                ptr := add(ptr, 32)
                r := calldataload(ptr)
                r := or(r, shr(4, r))
                r := or(r, shr(2, r))
                r := or(r, shr(1, r))
                r := and(r, mask)
                v := add(v, r)
            }

            // Count bytes in parallel
            v := add(v, shr(128, v))
            v := add(v, shr(64, v))
            v := add(v, shr(32, v))
            v := add(v, shr(16, v))
            v := and(v, 0xffff)
            v := add(and(v, 0xff), shr(8, v))

            // mstore(0, nonZeros)
            result := add(21000, add(mul(sub(calldatasize(), v), 4), mul(v, 16)))
            let words := shr(5, add(calldatasize(), 31))
            result := add(result, add(shr(9, mul(words, words)), mul(words, 3)))
            // mstore(0, add(21000, add(mul(sub(calldatasize(), v), 4), mul(v, 16))))
            // return(0, 32)
        }
        // return 21_000 + (msg.data.length * 16);
    }

    /**
     * @dev  Verify if shard exists, if the TSS signature is valid then increment shard's nonce.
     */
    function _verifySignature(Signature memory signature, bytes32 message) private view {
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
            _networks[network.id] = computeDomainSeparator(network.id, network.gateway);
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

                // If nonce is zero, it's a new shard, otherwise it is an existing shard which was previously revoked.
                if (nonce == 0) {
                    // if is a new shard shard, set its initial nonce to 1
                    shard.nonce = 1;
                } else {
                    // If the shard exists, the provided y-parity must match the original one
                    uint8 actualYParity = (status & SHARD_Y_PARITY) > 0 ? 1 : 0;
                    require(
                        actualYParity == yParity,
                        "the provided y-parity doesn't match the existing y-parity, cannot register shard"
                    );
                }

                // store the y-parity in the `KeyInfo`
                if (yParity > 0) {
                    // enable SHARD_Y_PARITY bitflag
                    status |= SHARD_Y_PARITY;
                } else {
                    // disable SHARD_Y_PARITY bitflag
                    status &= ~SHARD_Y_PARITY;
                }

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
    function updateKeys(Signature memory signature, UpdateKeysMessage memory message) public {
        bytes32 messageHash = message.eip712TypedHash(DOMAIN_SEPARATOR);
        _verifySignature(signature, messageHash);

        // Register shards pubkeys
        _updateKeys(messageHash, message.revoke, message.register);
    }

    // Deposit balance to refund callers of execute
    function deposit(bytes32 source, uint16 network) public payable {
        // Check if the source network is supported
        require(_networks[network] != bytes32(0), "unsupported network");
        _deposits[source][network] += msg.value;
    }

    // Execute GMP message
    function _execute(bytes32 payloadHash, GmpMessage memory message) private returns (uint8 status, bytes32 result) {
        // Verify if this GMP message was already executed
        GmpInfo storage gmp = _messages[payloadHash];
        require(gmp.status == GMP_STATUS_NOT_FOUND, "message already executed");

        // Update status to `pending` to prevent reentrancy attacks.
        gmp.status = GMP_STATUS_PENDING;
        gmp.blockNumber = uint64(block.number);

        // The encoded onGmpReceived call
        bytes memory data =
            abi.encodeCall(IGmpRecipient.onGmpReceived, (payloadHash, message.srcNetwork, message.source, message.data));

        // Execute GMP call
        bytes32[1] memory output = [bytes32(0)];
        bool success;
        address dest = message.dest;

        // Cap the GMP gas limit to 80% of the block gas limit
        // OBS: we assume the remaining 20% is enough for the Gateway execution, which is a safe assumption
        // once most EVM blockchains have gas limits above 10M and don't need more than 60k gas for the Gateway execution.
        uint256 maxGasLimit = (block.gaslimit / 5) * 4; // 80% of the block gas limit
        uint256 gasLimit = BranchlessMath.min(message.gasLimit, maxGasLimit);

        // Make sure the gas left is enough to execute the GMP message
        unchecked {
            // Subtract 5000 gas, 2600 (CALL) + 2400 (other instructions with some margin)
            uint256 gasAvailable = BranchlessMath.saturatingSub(gasleft(), 5000);
            // “all but one 64th", reference: https://eips.ethereum.org/EIPS/eip-150
            gasAvailable -= gasAvailable >> 6;
            require(gasAvailable > gasLimit, "gas left below message.gasLimit");
        }

        /// @solidity memory-safe-assembly
        assembly {
            // Using low-level assembly because the GMP is considered executed
            // regardless if the call reverts or not.
            let ptr := add(data, 32)
            let size := mload(data)

            // returns 1 if the call succeed, and 0 if it reverted
            success :=
                call(
                    gasLimit, // call gas limit (defined in the GMP message)
                    dest, // dest address
                    0, // value in wei to transfer (always zero for GMP)
                    ptr, // input memory pointer
                    size, // input size
                    output, // output memory pointer
                    32 // output size (fixed 32 bytes)
                )
        }

        // Get Result
        result = output[0];

        // Update GMP status
        status = uint8(BranchlessMath.select(success, GMP_STATUS_SUCCESS, GMP_STATUS_REVERTED));

        // Persist result and status on storage
        gmp.result = result;
        gmp.status = status;

        // Emit event
        emit GmpExecuted(payloadHash, message.source, message.dest, status, result);
    }

    /**
     * Execute GMP message
     * @param signature Schnorr signature
     * @param message GMP message
     */
    function execute(Signature memory signature, GmpMessage memory message)
        public
        returns (uint8 status, bytes32 result)
    {
        uint256 startGas = gasleft();

        // Theoretically we could remove the destination network field
        // and fill it up with the network id of the contract, then the signature will fail.
        require(message.destNetwork == NETWORK_ID, "invalid gmp network");
        require(_networks[message.srcNetwork] != bytes32(0), "unsupported source network");

        bytes32 messageHash = message.eip712TypedHash(DOMAIN_SEPARATOR);
        _verifySignature(signature, messageHash);
        (status, result) = _execute(messageHash, message);
        uint256 deposited = _deposits[message.source][message.srcNetwork];

        // Calculate a gas refund, capped to protect against huge spikes in `tx.gasprice`
        // that could drain funds unnecessarily. During these spikes, relayers should back off.
        uint256 gasUsed = _transactionBaseGas() + (startGas - gasleft()) + EXECUTE_GAS_DIFF;
        uint256 refund = gasUsed * tx.gasprice;
        require(deposited >= refund, "deposit below max refund");
        _deposits[message.source][message.srcNetwork] = deposited - refund;
        payable(msg.sender).transfer(refund);
    }

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
        // Check if the destination network is supported
        bytes32 domainSeparator = _networks[destinationNetwork];
        require(domainSeparator != bytes32(0), "unsupported network");

        // Check if the msg.sender is a contract or an EOA
        uint256 isContract = BranchlessMath.toUint(tx.origin != msg.sender);

        // We use 20 bytes for the address and 1 bit for contract flag
        bytes32 source = bytes32((isContract << 160) | uint256(uint160(msg.sender)));

        // Salt is equal to the previous message id (EIP-712 hash), this allows us to establish a sequence and eaily query the message history.
        bytes32 prevHash = prevMessageHash;

        // if the messageHash is the first message, we use a zero salt
        uint256 salt = BranchlessMath.select(prevHash == FIRST_MESSAGE_PLACEHOLDER, 0, uint256(prevHash));

        // Create GMP message and update prevMessageHash
        GmpMessage memory message =
            GmpMessage(source, NETWORK_ID, destinationAddress, destinationNetwork, executionGasLimit, salt, data);
        prevHash = message.eip712TypedHash(domainSeparator);
        prevMessageHash = prevHash;

        emit GmpCreated(prevHash, source, destinationAddress, destinationNetwork, executionGasLimit, salt, data);
        return prevHash;
    }
}
