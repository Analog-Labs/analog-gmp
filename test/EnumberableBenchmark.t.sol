// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {EnumerableSet as OZEnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableSet} from "../src/utils/EnumerableSet.sol";
import {StoragePtr, Pointer} from "../src/utils/Pointer.sol";

contract OZEnumberableSetContract {
    using OZEnumerableSet for OZEnumerableSet.Bytes32Set;

    OZEnumerableSet.Bytes32Set internal set;

    function add(bytes32 value) external {
        set.add(value);
    }

    function remove(bytes32 value) external {
        set.remove(value);
    }

    function contains(bytes32 value) external view returns (bool) {
        return set.contains(value);
    }

    function at(uint256 index) external view returns (bytes32) {
        return set.at(index);
    }

    function length() external view returns (uint256) {
        return set.length();
    }
}

contract CurrentEnumberableSet {
    using EnumerableSet for EnumerableSet.Map;

    EnumerableSet.Map internal set;

    function add(bytes32 value) external {
        set.add(value);
    }

    function remove(bytes32 value) external {
        set.remove(value);
    }

    function contains(bytes32 value) external view returns (bool) {
        return set.has(value);
    }

    function at(uint256 index) external view returns (bytes32 key, StoragePtr ptr) {
        (key, ptr) = set.at(index);
    }

    function length() external view returns (uint256) {
        return set.length();
    }
}

contract EnumerableBenchmark is Test {
    bytes32[] testValues;
    uint256 constant TEST_DATA_SIZE = 100;

    OZEnumberableSetContract oz;
    CurrentEnumberableSet current;

    function setUp() public {
        oz = new OZEnumberableSetContract();
        current = new CurrentEnumberableSet();
        testValues = generateBytes32Array(TEST_DATA_SIZE);
    }

    function testAddOperations() public {
        uint256 totalOZGas;
        uint256 totalAnalogGas;
        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            bytes32 value = testValues[i];

            uint256 gasBefore = gasleft();
            oz.add(value);
            totalOZGas += gasBefore - gasleft();

            gasBefore = gasleft();
            current.add(value);
            totalAnalogGas += gasBefore - gasleft();
        }
        uint256 gasDifference = totalOZGas - totalAnalogGas;

        console.log("\nGas report for Add:", TEST_DATA_SIZE);
        console.log("OZ took: %d", totalOZGas);
        console.log("current took: %d", totalAnalogGas);
        console.log("Difference: %d", gasDifference);
    }

    function testRemoveOperations() public {
        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            oz.add(testValues[i]);
            current.add(testValues[i]);
        }

        uint256 totalOZGas;
        uint256 totalAnalogGas;

        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            bytes32 value = testValues[i];

            uint256 gasBefore = gasleft();
            oz.remove(value);
            totalOZGas += gasBefore - gasleft();

            gasBefore = gasleft();
            current.remove(value);
            totalAnalogGas += gasBefore - gasleft();
        }

        uint256 gasDifference = totalOZGas - totalAnalogGas;

        console.log("\nGas report for remove:", TEST_DATA_SIZE);
        console.log("OZ took: %d", totalOZGas);
        console.log("current took: %d", totalAnalogGas);
        console.log("Difference: %d", gasDifference);
    }

    function testAtOperations() public {
        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            oz.add(testValues[i]);
            current.add(testValues[i]);
        }

        uint256 totalOZGas;
        uint256 totalAnalogGas;

        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            uint256 gasBefore = gasleft();
            oz.at(i);
            totalOZGas += gasBefore - gasleft();

            gasBefore = gasleft();
            current.at(i);
            totalAnalogGas += gasBefore - gasleft();
        }

        uint256 gasDifference = totalOZGas > totalAnalogGas ? totalOZGas - totalAnalogGas : totalAnalogGas - totalOZGas;

        console.log("\nGas report for at:", TEST_DATA_SIZE);
        console.log("OZ took: %d", totalOZGas);
        console.log("current took: %d", totalAnalogGas);
        console.log("Difference: %d", gasDifference);
    }

    function testLengthOperations() public {
        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            oz.add(testValues[i]);
            current.add(testValues[i]);
        }

        uint256 totalOZGas;
        uint256 totalAnalogGas;

        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            uint256 gasBefore = gasleft();
            oz.length();
            totalOZGas += gasBefore - gasleft();

            gasBefore = gasleft();
            current.length();
            totalAnalogGas += gasBefore - gasleft();
        }

        uint256 gasDifference = totalOZGas > totalAnalogGas ? totalOZGas - totalAnalogGas : totalAnalogGas - totalOZGas;

        console.log("\nGas report for at:", TEST_DATA_SIZE);
        console.log("OZ took: %d", totalOZGas);
        console.log("current took: %d", totalAnalogGas);
        console.log("Difference: %d", gasDifference);
    }

    function testContainsOperations() public {
        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            oz.add(testValues[i]);
            current.add(testValues[i]);
        }

        uint256 totalOZGas;
        uint256 totalAnalogGas;

        for (uint256 i = 0; i < TEST_DATA_SIZE; i++) {
            bytes32 value = testValues[i];

            uint256 gasBefore = gasleft();
            oz.contains(value);
            totalOZGas += gasBefore - gasleft();

            gasBefore = gasleft();
            current.contains(value);
            totalAnalogGas += gasBefore - gasleft();
        }

        uint256 gasDifference = totalOZGas > totalAnalogGas ? totalOZGas - totalAnalogGas : totalAnalogGas - totalOZGas;

        console.log("\nGas report for contains:", TEST_DATA_SIZE);
        console.log("OZ took: %d", totalOZGas);
        console.log("Current took: %d", totalAnalogGas);
        console.log("Difference: %d", gasDifference);
    }

    function generateBytes32Array(uint256 count) internal pure returns (bytes32[] memory) {
        bytes32[] memory values = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            values[i] = bytes32(uint256(i + 1));
        }
        return values;
    }
}
