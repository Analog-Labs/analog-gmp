// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Gateway.sol)

pragma solidity >=0.8.0;

import {Schnorr} from "@frost-evm/Schnorr.sol";
import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {GasUtils} from "./utils/GasUtils.sol";
import {ERC1967} from "./utils/ERC1967.sol";
import {UFloat9x56, UFloatMath} from "./utils/Float9x56.sol";
import {IGateway} from "./interfaces/IGateway.sol";
import {IGmpReceiver} from "./interfaces/IGmpReceiver.sol";
import {
    TssKey,
    GmpMessage,
    Route,
    Signature,
    GmpStatus,
    GmpSender
} from "./Primitives.sol";

abstract contract GatewayEIP712 {
    // EIP-712: Typed structured data hashing and signing
    // https://eips.ethereum.org/EIPS/eip-712
    uint16 internal immutable NETWORK_ID;
    address internal immutable PROXY_ADDRESS;

    constructor(uint16 networkId, address gateway) {
        NETWORK_ID = networkId;
        PROXY_ADDRESS = gateway;
    }
}

contract Gateway is IGateway, GatewayEIP712 {
    using BranchlessMath for uint256;
    using UFloatMath for UFloat9x56;

    event MessageExecuted(bytes32 id, GmpStatus status, bytes result);

    uint8 internal constant SHARD_ACTIVE = (1 << 0); // Shard active bitflag
    uint8 internal constant SHARD_Y_PARITY = (1 << 1); // Pubkey y parity bitflag

    /**
     * @dev Maximum size of the GMP payload
     */
    uint256 internal constant MAX_PAYLOAD_SIZE = 0x6000;

    // Shard data, maps the pubkey coordX (which is already collision resistant) to shard info.
    mapping(uint256 => TssKey) private _shards;

    // Network ID => Source network
    mapping(uint16 => Route) private _routes;

    // GMP message status
    mapping(bytes32 => GmpInfo) private _messages;

    // nonces
    mapping(address => uint64) private _nonces;

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

    function networkId() external view returns (uint16) {
        return NETWORK_ID;
    }

    // Converts a `TssKey` into an `KeyInfo` unique identifier
    function _tssKeyToShardId(TssKey memory tssKey) private pure returns (bytes32) {
        // The tssKey coord x is already collision resistant
        // if we are unsure about it, we can hash the coord and parity bit
        return bytes32(tssKey.xCoord);
    }

    function _messageId(GmpMessage memory message) private pure returns (bytes32) {
        // TODO:
    }

    function _relativeGasPrice(Route storage r) internal view returns (UFloat9x56) {
        return UFloatMath.fromRational(
            uint256(r.relativeGasPriceNumerator), uint256(r.relativeGasPriceDenominator));
    }

    /**
     * @dev  Verify if shard exists, if the TSS signature is valid then increment shard's nonce.
     */
    function _verifySignature(Signature calldata signature, uint256 xCoord, bytes memory data) private view {
        // Load shard from storage
        TssKey storage signer = _shards[xCoord];

        bytes32 hash = keccak256(data);

        // Load y parity bit, it must be 27 (even), or 28 (odd)
        // ref: https://ethereum.github.io/yellowpaper/paper.pdf
        uint8 yParity = BranchlessMath.ternaryU8(signer.yParity > 0, 28, 27);

        // Verify Signature
        require(
            Schnorr.verify(yParity, xCoord, uint256(hash), signature.e, signature.s),
            "invalid tss signature"
        );
    }
    
    /*//////////////////////////////////////////////////////////////
                               ADMIN LOGIC
    //////////////////////////////////////////////////////////////*/

    function admin() external view returns (address) {
        return ERC1967.getAdmin();
    }

    function setAdmin(address newAdmin) external {
        require(msg.sender == this.admin(), "unauthorized");
        ERC1967.setAdmin(newAdmin);
    }

    function upgrade(address newImplementation) external payable {
        require(msg.sender == this.admin(), "unauthorized");

        // Store the address of the implementation contract
        ERC1967.setImplementation(newImplementation);
    }

    // shards

    event RegisterShard(TssKey key);
    event UnregisterShard(TssKey key);

    function _registerShard(TssKey memory key) private {
        _shards[key.xCoord] = key;
        emit RegisterShard(key);
    }

    // Revoke TSS keys
    function _unregisterShard(TssKey memory key) private {
        delete _shards[key.xCoord];
        emit UnregisterShard(key);
    }

    function shards() external view returns (TssKey[] memory) {
        // TODO: return _shards
    }

    function setShards(TssKey[] memory keys) external payable {
        require(msg.sender == this.admin(), "unauthorized");
        // TODO: set _shards
    }

    // routes

    function routes() external view returns (Route[] memory) {
        // TODO: return _routes
    }

    /**
     * @dev set route using admin account
     */
    function setRoute(Route calldata r) external {
        require(msg.sender == this.admin(), "unauthorized");

        Route memory stored = _routes[r.networkId];

        stored.gateway = bytes32(BranchlessMath.ternary(uint256(r.gateway) != 0, uint256(r.gateway), uint256(r.gateway)));
        stored.gasLimit = BranchlessMath.ternaryU64(r.gasLimit != 0, r.gasLimit, stored.gasLimit);
        stored.baseFee = BranchlessMath.ternaryU128(r.baseFee != 0, r.baseFee, stored.baseFee);
        stored.relativeGasPriceNumerator = BranchlessMath.ternaryU128(
            r.relativeGasPriceNumerator != 0, r.relativeGasPriceNumerator, stored.relativeGasPriceNumerator);
        stored.relativeGasPriceDenominator = BranchlessMath.ternaryU128(
            r.relativeGasPriceDenominator != 0, r.relativeGasPriceDenominator, stored.relativeGasPriceDenominator);

        _routes[r.networkId] = stored;
    }

    // Execute GMP message
    function _executeMessage(GmpMessage calldata message) private {
        bytes32 id = _messageId(message);

        // Verify if this GMP message was already executed
        GmpInfo storage gmp = _messages[id];
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
        address dest = message.local;
        bytes memory data = message.data;
        bytes memory result;
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
                    gasLimit, // call gas limit defined in the GMP message or 50% of the block gas limit
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
        GmpStatus status = GmpStatus(BranchlessMath.ternary(success, uint256(GmpStatus.SUCCESS), uint256(GmpStatus.REVERT)));

        // Persist gmp execution status on storage
        gmp.status = status;

        // Emit event
        emit MessageExecuted(id, status, result);
    }

    /**
     * Execute GMP message
     * @param signature Schnorr signature
     * @param message GMP message
     */
    function execute(Signature calldata signature, uint256 xCoord, bytes memory message) external
    {
        uint256 initialGas = gasleft();
        // Add the solidity selector overhead to the initial gas, this way we guarantee that
        // the `initialGas` represents the actual gas that was available to this contract.
        initialGas = initialGas.saturatingAdd(453);

        // Verify the signature
        _verifySignature(signature, xCoord, message);

        // TODO: parse and execute message

        // Refund the chronicle gas
        unchecked {
            // Compute GMP gas used
            uint256 gasUsed = 7214;
            gasUsed = gasUsed.saturatingAdd(GasUtils.txBaseCost());
            gasUsed = gasUsed.saturatingAdd(GasUtils.proxyOverheadGasCost(uint16(msg.data.length), 64));
            gasUsed = gasUsed.saturatingAdd(initialGas - gasleft());

            // Compute refund amount
            uint256 refund = BranchlessMath.min(gasUsed.saturatingMul(tx.gasprice), address(this).balance);

            /// @solidity memory-safe-assembly
            assembly {
                pop(call(gas(), caller(), refund, 0, 0, 0, 0))
            }
        }
    }

    /**
     * @dev Send message from this chain to another chain.
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
    ) external payable returns (bytes32) {
        // Check if the message data is too large
        require(data.length <= MAX_PAYLOAD_SIZE, "msg data too large");

        // Check if the destination network is supported
        Route storage info = _routes[destinationNetwork];

        // Check if the sender has deposited enougth funds to execute the GMP message
        {
            uint256 nonZeros = GasUtils.countNonZerosCalldata(data);
            uint256 zeros = data.length - nonZeros;
            uint256 msgPrice = GasUtils.estimateWeiCost(
                _relativeGasPrice(info), info.baseFee, uint16(nonZeros), uint16(zeros), executionGasLimit
            );
            require(msg.value >= msgPrice, "insufficient tx value");
        }

        // We use 20 bytes for represent the address and 1 bit for the contract flag
        GmpSender source = GmpSender.wrap(bytes32(uint256(uint160(msg.sender))));
        uint64 nonce = _nonces[msg.sender];
        _nonces[msg.sender] = nonce + 1;
        GmpMessage memory message =
            GmpMessage(source, NETWORK_ID, destinationAddress, destinationNetwork, executionGasLimit, nonce, data);
        bytes32 id = _messageId(message);
        emit MessageReceived(id, message);
        return id;
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
        Route storage r = _routes[networkid];
        uint256 baseFee = uint256(r.baseFee);
        UFloat9x56 relativeGasPrice = _relativeGasPrice(r);

        // Verify if the network exists
        require(baseFee > 0 || UFloat9x56.unwrap(relativeGasPrice) > 0, "unsupported network");

        // if the message data is too large, we use the maximum base fee.
        baseFee = BranchlessMath.ternary(messageSize > MAX_PAYLOAD_SIZE, 2 ** 256 - 1, baseFee);

        // Estimate the cost
        return GasUtils.estimateWeiCost(relativeGasPrice, baseFee, uint16(messageSize), 0, gasLimit);
    }
}
