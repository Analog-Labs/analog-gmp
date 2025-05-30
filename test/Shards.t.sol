// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (src/storage/Routes.sol)
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ShardStore} from "../src/storage/Shards.sol";
import {TssKey} from "../src/Primitives.sol";
import {Signer} from "frost-evm/sol/Signer.sol";

contract ShardStoreTest is Test {
    using ShardStore for ShardStore.MainStorage;

    TssKey[3] keys;
    TssKey invalidKey;

    function setUp() public {
        // 4 gives parity 27
        // 5 gives parity 28
        for (uint16 i = 4; i <= 6; i++) {
            Signer signer = new Signer(i + 1);
            keys[i - 4] = TssKey({yParity: signer.yParity(), xCoord: signer.xCoord()});
        }
        invalidKey = TssKey({yParity: keys[2].yParity - 2, xCoord: keys[2].xCoord});
    }

    function getStore() internal pure returns (ShardStore.MainStorage storage) {
        return ShardStore.getMainStorage();
    }

    function externalRegister(TssKey calldata key) external returns (bool) {
        return getStore().register(key);
    }

    function externalRegisterTssKeys(TssKey[] calldata shard_keys) external {
        for (uint256 i = 0; i < shard_keys.length; i++) {
            getStore().register(shard_keys[i]);
        }
    }

    function externalReplaceTssKeys(TssKey[] calldata shard_keys) external returns (TssKey[] memory, TssKey[] memory) {
        return getStore().replaceTssKeys(shard_keys);
    }

    function externalRevoke(TssKey calldata key) external returns (bool) {
        return getStore().revoke(key);
    }

    function externalAt(uint256 index) external view {
        getStore().at(index);
    }

    function externalGet(ShardStore.ShardID shard_id) external view {
        getStore().get(shard_id);
    }

    function registerKeyCall(TssKey memory key) internal returns (bool) {
        bytes memory callData = abi.encodeWithSelector(this.externalRegister.selector, key);
        (bool success, bytes memory returnData) = address(this).call(callData);
        require(success, "Register call failed");
        return abi.decode(returnData, (bool));
    }

    function registerKeysCall(TssKey[] memory shard_keys) internal {
        bytes memory callData = abi.encodeWithSelector(this.externalRegisterTssKeys.selector, shard_keys);
        (bool success,) = address(this).call(callData);
        require(success, "Register keys call failed");
    }

    function replaceKeysCall(TssKey[] memory shard_keys)
        internal
        returns (TssKey[] memory created, TssKey[] memory revoked)
    {
        bytes memory callData = abi.encodeWithSelector(this.externalReplaceTssKeys.selector, shard_keys);
        (bool success, bytes memory returnData) = address(this).call(callData);
        require(success, "Replace keys call failed");
        return abi.decode(returnData, (TssKey[], TssKey[]));
    }

    function revokeKeyCall(TssKey memory key) internal returns (bool) {
        bytes memory callData = abi.encodeWithSelector(this.externalRevoke.selector, key);
        (bool success, bytes memory returnData) = address(this).call(callData);
        require(success, "Revoke call failed");
        return abi.decode(returnData, (bool));
    }

    /// Tests
    function testRegisterNewShard() public {
        uint256 coords = keys[0].xCoord;
        uint8 y_parity = keys[0].yParity;
        TssKey memory newKey = TssKey({yParity: y_parity, xCoord: coords});

        bool registered = registerKeyCall(newKey);
        assertTrue(registered, "New shard should be registered");

        ShardStore.ShardID shardId = ShardStore.ShardID.wrap(bytes32(coords));
        assertTrue(getStore().has(shardId), "Shard should exist");
        assertEq(getStore().length(), 1, "Store should contain one shard");

        ShardStore.ShardInfo memory stored = getStore().get(shardId);
        assertEq(stored.yParity, y_parity, "Y-parity mismatch");
        assertEq(stored.nonce, 1, "Nonce should be 1 for new shard");
        assertEq(stored.createdAtBlock, block.number, "Created block mismatch");
    }

    function testRegisterExistingShard() public {
        testRegisterNewShard();

        TssKey memory existingKey = keys[0];

        bool registered = registerKeyCall(existingKey);
        assertFalse(registered, "Existing shard should not be re-registered");
        assertEq(getStore().length(), 1, "Store length should remain unchanged");
    }

    function testRegisterInvalidYParity() public {
        vm.expectRevert(ShardStore.InvalidYParity.selector);
        registerKeyCall(invalidKey);
    }

    function testRegisterTssKeysBatch() public {
        TssKey[] memory dynamicKeys = new TssKey[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            dynamicKeys[i] = keys[i];
        }
        registerKeysCall(dynamicKeys);

        assertEq(getStore().length(), 3, "All keys should be registered");
        for (uint256 i = 0; i < keys.length; i++) {
            ShardStore.ShardID shardId = ShardStore.ShardID.wrap(bytes32(dynamicKeys[i].xCoord));
            assertTrue(getStore().has(shardId), "Each shard should exist");
        }
    }

    function testReplaceTssKeys() public {
        TssKey[] memory initialKeys = new TssKey[](2);
        initialKeys[0] = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});
        initialKeys[1] = TssKey({yParity: keys[1].yParity, xCoord: keys[1].xCoord});
        registerKeysCall(initialKeys);

        TssKey[] memory newKeys = new TssKey[](2);
        newKeys[0] = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});
        newKeys[1] = TssKey({yParity: keys[2].yParity, xCoord: keys[2].xCoord});

        (TssKey[] memory created, TssKey[] memory revoked) = replaceKeysCall(newKeys);

        assertEq(created.length, 1, "One key should be created");
        assertEq(created[0].xCoord, keys[2].xCoord, "Wrong created key");

        assertEq(revoked.length, 1, "One key should be revoked");
        assertEq(revoked[0].xCoord, keys[1].xCoord, "Wrong revoked key");

        assertEq(getStore().length(), 2, "Store should contain two shards");
    }

    function testRevokeShard() public {
        testRegisterNewShard();

        TssKey memory keyToRevoke = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});

        bool revoked = revokeKeyCall(keyToRevoke);
        assertTrue(revoked, "Key should be revoked");

        ShardStore.ShardID shardId = ShardStore.ShardID.wrap(bytes32(keys[0].xCoord));
        assertFalse(getStore().has(shardId), "Shard should not exist after revocation");
        assertEq(getStore().length(), 0, "Store should be empty");
    }

    function testRevokeNonExistentShard() public {
        TssKey memory nonExistentKey = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});

        bool revoked = revokeKeyCall(nonExistentKey);
        assertFalse(revoked, "Non-existent key revocation should return false");
    }

    function testRevokeWithWrongYParity() public {
        TssKey memory originalKey = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});
        registerKeyCall(originalKey);

        TssKey memory wrongParityKey = TssKey({yParity: keys[0].yParity - 2, xCoord: keys[0].xCoord});

        vm.expectRevert(ShardStore.YParityMismatch.selector);
        revokeKeyCall(wrongParityKey);
    }

    function testGetNonExistentShard() public {
        ShardStore.ShardID nonExistentId = ShardStore.ShardID.wrap(bytes32(keys[0].xCoord));
        vm.expectRevert(abi.encodeWithSelector(ShardStore.ShardNotExists.selector, nonExistentId));
        this.externalGet(nonExistentId);
    }

    function testAtOutOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(ShardStore.IndexOutOfBounds.selector, 0));
        this.externalAt(0);
    }

    function testListShards() public {
        TssKey[] memory newKeys = new TssKey[](3);
        newKeys[0] = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});
        newKeys[1] = TssKey({yParity: keys[1].yParity, xCoord: keys[1].xCoord});
        newKeys[2] = TssKey({yParity: keys[2].yParity, xCoord: keys[2].xCoord});
        registerKeysCall(newKeys);

        TssKey[] memory listed = getStore().listShards();
        assertEq(listed.length, 3, "Should list all shards");

        bool[] memory found = new bool[](3);
        for (uint256 i = 0; i < listed.length; i++) {
            for (uint256 j = 0; j < newKeys.length; j++) {
                if (listed[i].xCoord == newKeys[j].xCoord && listed[i].yParity == newKeys[j].yParity) {
                    found[j] = true;
                    break;
                }
            }
        }

        for (uint256 i = 0; i < found.length; i++) {
            assertTrue(found[i], "All original keys should be found in listing");
        }
    }

    function testAtValidIndex() public {
        TssKey memory key = TssKey({yParity: keys[0].yParity, xCoord: keys[0].xCoord});
        registerKeyCall(key);

        (ShardStore.ShardID shardId, ShardStore.ShardInfo memory info) = getStore().at(0);
        assertEq(ShardStore.ShardID.unwrap(shardId), bytes32(keys[0].xCoord), "Shard ID mismatch");
        assertEq(info.yParity, keys[0].yParity, "Y-parity mismatch");
        assertEq(info.nonce, 1, "Nonce mismatch");
    }
}
