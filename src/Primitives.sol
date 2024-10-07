// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/Primitives.sol)

pragma solidity >=0.8.0;

import {BranchlessMath} from "./utils/BranchlessMath.sol";
import {UFloatMath, UFloat9x56} from "./utils/Float9x56.sol";

/**
 * @dev GmpSender is the sender of a GMP message
 */
type GmpSender is bytes32;

/**
 * @dev Tss public key
 * @param yParity public key y-coord parity, the contract converts it to 27/28
 * @param xCoord affine x-coordinate
 */
struct TssKey {
    uint8 yParity;
    uint256 xCoord;
}

/**
 * @dev Schnorr signature.
 * OBS: what is actually signed is: keccak256(abi.encodePacked(R, parity, px, nonce, message))
 * Where `parity` is the public key y coordinate stored in the contract, and `R` is computed from `e` and `s` parameters.
 * @param xCoord public key x coordinates, y-parity is stored in the contract
 * @param e Schnorr signature e component
 * @param s Schnorr signature s component
 */
struct Signature {
    uint256 e;
    uint256 s;
}

/**
 * @dev GMP payload, this is what the timechain creates as task payload
 * @param source Pubkey/Address of who send the GMP message
 * @param srcNetwork Source chain identifier (for ethereum networks it is the EIP-155 chain id)
 * @param dest Destination/Recipient contract address
 * @param destNetwork Destination chain identifier (it's the EIP-155 chain_id for ethereum networks)
 * @param gasLimit gas limit of the GMP call
 * @param salt Message salt, useful for sending two messages with same content
 * @param data message data with no specified format
 */
struct GmpMessage {
    GmpSender foreign;
    uint16 foreignNetwork;
    address local;
    uint128 gasLimit;
    uint128 gasCost;
    uint64 nonce;
    bytes data;
}

/**
 * @dev Message payload used to update the network info.
 * @param networkId Domain EIP-712 - Replay Protection Mechanism.
 * @param domainSeparator Domain EIP-712 - Replay Protection Mechanism.
 * @param gasLimit The maximum amount of gas we allow on this particular network.
 * @param relativeGasPrice Gas price of destination chain, in terms of the source chain token.
 * @param baseFee Base fee for cross-chain message approval on destination, in terms of source native gas token.
 * @param mortality maximum block in which this message is valid.
 */
struct Route {
    uint16 networkId;
    bytes32 gateway;
    uint128 relativeGasPriceNumerator;
    uint128 relativeGasPriceDenominator;
    uint64 gasLimit;
    uint128 baseFee;
}

/**
 * @dev Status of a GMP message
 */
enum GmpStatus {
    NOT_FOUND,
    SUCCESS,
    REVERT,
    INSUFFICIENT_FUNDS,
    PENDING
}
