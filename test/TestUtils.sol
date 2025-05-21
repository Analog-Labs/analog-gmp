// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/TestUtils.sol)

pragma solidity >=0.8.0;

import {VmSafe, Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {Schnorr} from "../lib/frost-evm/sol/Schnorr.sol";
import {SECP256K1} from "../lib/frost-evm/sol/SECP256K1.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {
    GmpMessage,
    UpdateKeysMessage,
    Signature,
    TssKey,
    Network,
    NetworkID,
    Route,
    GmpStatus,
    PrimitiveUtils,
    GmpSender
} from "../src/Primitives.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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
    using BranchlessMath for uint256;

    // Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
    address internal constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm internal constant vm = Vm(VM_ADDRESS);

    /**
     * @dev Deploys a contract with the given bytecode
     */
    function deployContract(bytes memory bytecode) internal returns (address addr) {
        require(bytecode.length > 0, "Error: deploy code is empty");
        assembly ("memory-safe") {
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
        assembly ("memory-safe") {
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
     * @dev Count the number of non-zero bytes in a byte sequence.
     * Reference: https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
     */
    function countNonZeros(bytes memory data) internal pure returns (uint256 nonZeros) {
        assembly ("memory-safe") {
            // Efficient algorithm for counting non-zero bytes in parallel
            nonZeros := 0
            for {
                // 32 byte aligned pointer, ex: if data.length is 54, `ptr` starts at 32
                let ptr := add(data, and(add(mload(data), 31), 0xffffffe0))
            } gt(ptr, data) { ptr := sub(ptr, 32) } {
                // Normalize
                let v := mload(ptr)
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
        uint256 secret;
        assembly {
            mstore(0, entropy)
            secret := keccak256(0x00, 0x20)
        }
        while (secret >= Schnorr.Q) {
            assembly {
                mstore(0, secret)
                secret := keccak256(0x00, 0x20)
            }
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
    function _call(address addr, uint256 gasLimit, uint256 value, bytes memory data)
        private
        returns (uint256 gasUsed, bool success, bytes memory out)
    {
        require(gasleft() > gasLimit.saturatingAdd(5000), "insufficient gas");
        require(addr.code.length > 0, "Not a contract address");
        assembly ("memory-safe") {
            success :=
                call(
                    0x7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E, // Code Injection TAG
                    gasLimit, // gas limit
                    addr, // addr
                    value, // value
                    add(data, 32), // arg offset
                    mload(data), // arg size
                    0 // return offset
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
    function executeCall(address sender, address dest, uint256 gasLimit, uint256 value, bytes memory data)
        internal
        returns (uint256 executionCost, uint256 baseCost, bytes memory out)
    {
        bool success;
        (executionCost, baseCost, success, out) = tryExecuteCall(sender, dest, gasLimit, value, data);
        // Revert if the execution failed
        assembly {
            if iszero(success) { revert(add(out, 32), mload(out)) }
        }
    }

    // Execute a contract call and calculate the acurrate execution gas cost
    function tryExecuteCall(address sender, address dest, uint256 gasLimit, uint256 value, bytes memory data)
        internal
        returns (uint256 executionCost, uint256 baseCost, bool success, bytes memory out)
    {
        // Guarantee there's enough gas to execute the call
        {
            uint256 gasRequired = (gasLimit * 64) / 63;
            gasRequired += 50_000;
            require(gasleft() > gasRequired, "insufficient gas left to execute call");
        }

        // Compute the base tx cost (21k + 4 * zeros + 16 * nonZeros)
        baseCost = calculateBaseCost(data);

        // Decrement sender base cost and value
        {
            uint256 txFees = gasLimit.saturatingMul(tx.gasprice);
            require(sender.balance >= txFees.saturatingAdd(value), "account has no sufficient funds");
            vm.deal(sender, sender.balance - txFees);
            gasLimit = gasLimit.saturatingSub(baseCost);
        }

        // Execute
        {
            (VmSafe.CallerMode callerMode, address msgSender, address txOrigin) =
                setCallerMode(VmSafe.CallerMode.RecurrentPrank, sender, sender);
            (executionCost, success, out) = _call(dest, gasLimit, value, data);
            setCallerMode(callerMode, msgSender, txOrigin);
        }

        // Refund unused gas
        uint256 refund = gasLimit.saturatingSub(executionCost).saturatingMul(tx.gasprice);
        if (refund > 0) {
            vm.deal(sender, sender.balance + refund);
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

    /**
     * @dev Deploy a new Gateway and GatewayProxy contracts.
     */
    function setupGateway(VmSafe.Wallet memory admin, uint16 network) internal returns (IGateway gw) {
        vm.startPrank(admin.addr, admin.addr);
        // GatewayProxy proxy = new GatewayProxy(admin.addr);

        Gateway gateway = new Gateway();
        bytes memory initData = abi.encodeWithSelector(Gateway.initialize.selector, network);
        ERC1967Proxy proxy = new ERC1967Proxy(address(gateway), initData);
        console.log("Implementation:", address(gateway));
        console.log("Proxy:", address(proxy));

        vm.deal(address(proxy), 10 ether);
        console.log("deel done");
        vm.stopPrank();
        console.log("stopping prank");
        return IGateway(address(proxy));
    }

    function setMockShard(VmSafe.Wallet memory admin, address gateway, VmSafe.Wallet memory shard) internal {
        SigningKey memory signer = TestUtils.createSigner(shard.privateKey);
        TssKey memory key =
            TssKey({yParity: SigningUtils.yParity(signer) == 28 ? 3 : 2, xCoord: SigningUtils.xCoord(signer)});
        Gateway gw = Gateway(payable(gateway));
        vm.startPrank(admin.addr, admin.addr);
        gw.setShard(key);
        vm.stopPrank();
    }

    function setMockRoute(VmSafe.Wallet memory admin, address gateway, uint16 network) internal {
        Gateway gw = Gateway(payable(gateway));
        vm.startPrank(admin.addr, admin.addr);
        gw.setRoute(
            Route({
                networkId: NetworkID.wrap(network),
                gasLimit: 1_000_000,
                baseFee: 0,
                gateway: bytes32(uint256(1)),
                relativeGasPriceNumerator: 1,
                relativeGasPriceDenominator: 1
            })
        );
        vm.stopPrank();
    }
}

library VerifyingUtils {
    function addr(VerifyingKey memory pubkey) internal pure returns (address) {
        uint256 hash;
        assembly {
            hash := keccak256(pubkey, 0x40)
        }
        return address(uint160(hash));
    }

    function yParity(VerifyingKey memory pubkey) internal pure returns (uint8) {
        return uint8(pubkey.py % 2) + 27;
    }

    function challenge(VerifyingKey memory pubkey, bytes32 hash, address r) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(r, yParity(pubkey), pubkey.px, uint256(hash))));
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
}

library SigningUtils {
    function addr(SigningKey memory signer) internal pure returns (address) {
        return VerifyingUtils.addr(signer.pubkey);
    }

    function yParity(SigningKey memory signer) internal pure returns (uint8) {
        return uint8(signer.pubkey.py % 2) + 27;
    }

    function xCoord(SigningKey memory signer) internal pure returns (uint256) {
        return signer.pubkey.px;
    }

    function challenge(SigningKey memory signer, bytes32 hash, address r) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(r, yParity(signer), signer.pubkey.px, uint256(hash))));
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

    function verifyPrehash(SigningKey memory signer, bytes32 prehash, uint256 c, uint256 z)
        internal
        pure
        returns (bool)
    {
        return Schnorr.verify(yParity(signer), signer.pubkey.px, uint256(prehash), c, z);
    }

    function verify(SigningKey memory signer, bytes memory message, uint256 c, uint256 z)
        internal
        pure
        returns (bool)
    {
        return verifyPrehash(signer, keccak256(message), c, z);
    }
}
