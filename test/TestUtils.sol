// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/TestUtils.sol)

pragma solidity >=0.8.0;

import {VmSafe, Vm} from "forge-std/Vm.sol";
import {Schnorr} from "@frost-evm/Schnorr.sol";
import {SECP256K1} from "@frost-evm/SECP256K1.sol";

struct VerifyingKey {
    uint256 px;
    uint256 py;
}

struct SigningKey {
    uint256 secret;
    VerifyingKey pubkey;
}

/**
 * @dev Utilities for testing purposes
 */
library TestUtils {
    // Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
    address internal constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

    Vm internal constant vm = Vm(VM_ADDRESS);

    /**
     * @dev Deploys a contract with the given bytecode
     */
    function deployContract(bytes memory bytecode) internal returns (address addr) {
        require(bytecode.length > 0, "Error: deploy code is empty");
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := add(bytecode, 32)
            let size := mload(bytecode)
            addr := create(0, ptr, size)
        }
        require(addr != address(0), "Error: failed to deploy contract");
    }

    /**
     * @dev  Delegate call to another contract bytecode
     *  This execute the code of another contract in the context of the current contract
     */
    function delegateCall(address contractAddr, bytes memory data)
        internal
        returns (bool success, bytes memory output)
    {
        require(contractAddr.code.length > 0, "Error: provided address is not a contract");
        /// @solidity memory-safe-assembly
        assembly {
            success :=
                delegatecall(
                    gas(), // call gas limit
                    contractAddr, // dest address
                    add(32, data), // input memory pointer
                    mload(data), // input size
                    0, // output memory pointer
                    0 // output size
                )

            // Alloc memory for the output
            output := mload(0x40)
            let ptr := add(output, 32)
            let size := returndatasize()
            mstore(0x40, add(ptr, size)) // Increment free memory pointer

            // Store return data size
            mstore(output, size)

            // Copy delegatecall output to memory
            returndatacopy(ptr, 0, size)
        }
    }

    /**
     * @dev Count non-zero bytes in a 256bit word in parallel
     * Reference: https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
     */
    function countNonZeros(bytes memory data) internal pure returns (uint256 nonZeros) {
        /// @solidity memory-safe-assembly
        assembly {
            nonZeros := 0
            for {
                let len := mload(data)
                let ptr := add(data, 32)
                let end := add(ptr, len)
            } lt(ptr, end) { ptr := add(ptr, 32) } {
                // Remove padding
                let v := mload(ptr)
                {
                    let padding := sub(end, ptr)
                    padding := mul(lt(padding, 32), padding)
                    v := shr(padding, v)
                }

                // Normalize
                v := or(v, shr(4, v))
                v := or(v, shr(2, v))
                v := or(v, shr(1, v))
                v := and(v, 0x0101010101010101010101010101010101010101010101010101010101010101)

                // Count bytes in parallel
                v := add(v, shr(128, v))
                v := add(v, shr(64, v))
                v := add(v, shr(32, v))
                v := add(v, shr(16, v))
                v := add(v, shr(8, v))
                v := and(v, 0xff)
                nonZeros := add(nonZeros, v)
            }
        }
    }

    /**
     * @dev Calculate the tx base cost.
     * formula: 21000 + zeros * 4 + nonZeros * 16
     * Reference: https://eips.ethereum.org/EIPS/eip-2028
     */
    function calculateBaseCost(bytes memory txData) internal pure returns (uint256 baseCost) {
        uint256 nonZeros = countNonZeros(txData);
        uint256 zeros = txData.length - nonZeros;
        baseCost = 21_000 + (nonZeros * 16) + (zeros * 4);
    }

    /**
     * @dev Calculate the tx base cost.
     * formula: 21000 + zeros * 4 + nonZeros * 16
     * Reference: https://eips.ethereum.org/EIPS/eip-2028
     */
    function memExpansionCost(uint256 size) internal pure returns (uint256) {
        uint256 words = (size + 31) / 32;
        return ((words ** 2) / 512) + (words * 3);
    }

    /**
     * @dev Generate a new account account from the calldata
     * This will generate a unique deterministic address for each test case
     */
    function createTestAccount(uint256 initialBalance) internal returns (address account) {
        // Generate a new account address from the calldata
        // This will generate a unique deterministic address for each test case
        account = address(uint160(uint256(keccak256(msg.data))));
        vm.deal(account, initialBalance);
    }

    /**
     * @dev Generate a new account account from the calldata
     */
    function createTestAccount() internal returns (address account) {
        // Create an account with 100 ether
        account = createTestAccount(100 ether);
    }

    /**
     * @dev Convert an address to GMP bytes32 identifier
     */
    function source(address account, bool isContract) internal pure returns (bytes32) {
        uint256 contractFlag = isContract ? 1 << 160 : 0;
        return bytes32(contractFlag | uint256(uint160(account)));
    }

    /**
     * @dev Convert an address to GMP bytes32 identifier
     */
    function source(address account) internal view returns (bytes32) {
        return source(account, account.code.length > 0);
    }

    /**
     * @dev Creates a new TSS signer
     */
    function createSigner(uint256 secret) internal pure returns (SigningKey memory) {
        require(secret != 0, "secret must be greater than 0");
        require(secret < Schnorr.Q, "secret must be less than secp256k1 group order");
        (uint256 px, uint256 py) = SECP256K1.publicKey(secret);
        return SigningKey({secret: secret, pubkey: VerifyingKey({px: px, py: py})});
    }

    /**
     * @dev Creates a new TSS signer
     */
    function signerFromEntropy(bytes32 entropy) internal pure returns (SigningKey memory) {
        uint256 secret = uint256(entropy);
        while (secret >= Schnorr.Q) {
            secret = uint256(keccak256(abi.encodePacked(secret)));
        }
        return createSigner(secret);
    }

    /**
     * @dev Creates an unique TSS signer per test case
     */
    function createSigner() internal pure returns (SigningKey memory) {
        return signerFromEntropy(keccak256(msg.data));
    }

    // Workaround for set the tx.gasLimit, currently is not possible to define the gaslimit in foundry
    // Reference: https://github.com/foundry-rs/foundry/issues/2224
    function _call(address addr, uint256 gasLimit, bytes memory data)
        private
        returns (uint256 gasUsed, bool success, bytes memory out)
    {
        require(gasleft() > (gasLimit + 5000), "insufficient gas");
        require(addr.code.length > 0, "Not a contract address");
        /// @solidity memory-safe-assembly
        assembly {
            success :=
                call(
                    0x7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E, // gas limit
                    addr, // addr
                    gasLimit, // value
                    add(data, 32),
                    mload(data),
                    0,
                    0
                )
            gasUsed := mload(0)

            out := mload(0x40)
            let size := returndatasize()
            mstore(out, size)
            let ptr := add(out, 32)
            returndatacopy(ptr, 0, size)
            mstore(0x40, add(ptr, size))
        }
    }

    // Execute a contract call and calculate the acurrate execution gas cost
    function executeCall(address sender, address dest, uint256 gasLimit, bytes memory data)
        internal
        returns (uint256 executionCost, uint256 baseCost, bytes memory out)
    {
        // Compute the base tx cost (21k + 4 * zeros + 16 * nonZeros)
        baseCost = calculateBaseCost(data);

        // Decrement sender base cost
        {
            uint256 gasRequired = baseCost + gasLimit;
            uint256 fees = gasRequired * tx.gasprice;
            require(sender.balance >= fees, "account has no sufficient funds");
            vm.deal(sender, sender.balance - fees);
        }

        // Execute
        (VmSafe.CallerMode callerMode, address msgSender, address txOrigin) =
            setCallerMode(VmSafe.CallerMode.RecurrentPrank, sender, sender);
        bool success;
        (executionCost, success, out) = _call(dest, gasLimit - baseCost, data);
        setCallerMode(callerMode, msgSender, txOrigin);

        // Refund unused gas
        uint256 refund = (gasLimit - executionCost) * tx.gasprice;
        if (refund > 0) {
            vm.deal(sender, sender.balance + refund);
        }

        // Revert if the execution failed
        assembly {
            if iszero(success) { revert(add(out, 32), mload(out)) }
        }
    }

    function setCallerMode(VmSafe.CallerMode callerMode, address msgSender, address txOrigin)
        internal
        returns (VmSafe.CallerMode prevCallerMode, address prevMsgSender, address prevTxOrigin)
    {
        (prevCallerMode, prevMsgSender, prevTxOrigin) = vm.readCallers();

        // Stop previous caller mode
        if (prevCallerMode == VmSafe.CallerMode.RecurrentBroadcast) {
            vm.stopBroadcast();
        } else if (prevCallerMode == VmSafe.CallerMode.RecurrentPrank) {
            vm.stopPrank();
        }

        // Set new caller mode
        if (callerMode == VmSafe.CallerMode.Broadcast) {
            vm.broadcast(msgSender);
        } else if (callerMode == VmSafe.CallerMode.RecurrentBroadcast) {
            vm.startBroadcast(msgSender);
        } else if (callerMode == VmSafe.CallerMode.Prank) {
            vm.prank(msgSender, txOrigin);
        } else if (callerMode == VmSafe.CallerMode.RecurrentPrank) {
            vm.startPrank(msgSender, txOrigin);
        }
    }

    function prank(address msgSender, address txOrigin, function() f) internal {
        VmSafe.CallerMode callerMode = VmSafe.CallerMode.RecurrentPrank;
        (callerMode, msgSender, txOrigin) = setCallerMode(VmSafe.CallerMode.RecurrentPrank, msgSender, txOrigin);
        f();
        setCallerMode(callerMode, msgSender, txOrigin);
    }

    function prank(address msgSender, function() f) internal {
        VmSafe.CallerMode callerMode = VmSafe.CallerMode.RecurrentPrank;
        address txOrigin = msgSender;
        (callerMode, msgSender, txOrigin) = setCallerMode(VmSafe.CallerMode.RecurrentPrank, msgSender, txOrigin);
        f();
        setCallerMode(callerMode, msgSender, txOrigin);
    }
}

library SigningUtils {
    function yParity(VerifyingKey memory pubkey) internal pure returns (uint8) {
        return uint8(pubkey.py % 2) + 27;
    }

    function yParity(SigningKey memory signer) internal pure returns (uint8) {
        return yParity(signer.pubkey);
    }

    function challenge(VerifyingKey memory pubkey, bytes32 hash, address r) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(r, yParity(pubkey), pubkey.px, uint256(hash))));
    }

    function challenge(SigningKey memory signer, bytes32 hash, address r) internal pure returns (uint256) {
        return challenge(signer.pubkey, hash, r);
    }

    function signPrehashed(SigningKey memory signer, bytes32 hash, uint256 nonce)
        internal
        pure
        returns (uint256, uint256)
    {
        (uint256 rx, uint256 ry) = SECP256K1.publicKey(nonce);
        address r = SECP256K1.point_hash(rx, ry);
        uint256 c = challenge(signer, hash, r);
        uint256 z = addmod(nonce, mulmod(c, signer.secret, Schnorr.Q), Schnorr.Q);
        return (c, z);
    }

    function sign(SigningKey memory signer, bytes memory message, uint256 nonce)
        internal
        pure
        returns (uint256, uint256)
    {
        return signPrehashed(signer, keccak256(message), nonce);
    }

    function verifyPrehash(VerifyingKey memory pubkey, bytes32 prehash, uint256 c, uint256 z)
        internal
        pure
        returns (bool)
    {
        return Schnorr.verify(yParity(pubkey), pubkey.px, uint256(prehash), c, z);
    }

    function verify(VerifyingKey memory pubkey, bytes memory message, uint256 c, uint256 z)
        internal
        pure
        returns (bool)
    {
        return verifyPrehash(pubkey, keccak256(message), c, z);
    }

    function verifyPrehash(SigningKey memory signer, bytes32 prehash, uint256 c, uint256 z)
        internal
        pure
        returns (bool)
    {
        return verifyPrehash(signer.pubkey, prehash, c, z);
    }

    function verify(SigningKey memory signer, bytes memory message, uint256 c, uint256 z)
        internal
        pure
        returns (bool)
    {
        return verifyPrehash(signer.pubkey, keccak256(message), c, z);
    }
}
