// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (scripts/Upgrade.sol)

pragma solidity ^0.8.0;

import {FactoryUtils} from "@universal-factory/FactoryUtils.sol";
import {IUniversalFactory} from "@universal-factory/IUniversalFactory.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {NetworkID, NetworkIDHelpers} from "../src/NetworkID.sol";
import {ERC1967} from "../src/utils/ERC1967.sol";
import {BranchlessMath} from "../src/utils/BranchlessMath.sol";
import {UFloat9x56, UFloatMath} from "../src/utils/Float9x56.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {Gateway} from "../src/Gateway.sol";
import {
    TssKey,
    GmpMessage,
    UpdateKeysMessage,
    UpdateNetworkInfo,
    Signature,
    Network,
    GmpStatus,
    GmpSender,
    PrimitiveUtils
} from "../src/Primitives.sol";

contract MigrateGateway is Script {
    using NetworkIDHelpers for NetworkID;
    using FactoryUtils for IUniversalFactory;

    /**
     * @dev The codehash of the proxy contract
     */
    bytes32 internal constant PROXY_CODEHASH = 0x54afeb06256bce71659256132ac18f1515de3011aaec4fbd6fc7b0c00c7263d8;
    
    /**
     * @dev The minimal balance required to deploy the proxy contract
     */
    uint256 internal constant MINIMAL_DEPLOYER_BALANCE = 0.5 ether;

    /**
     * @dev Universal Factory used to deploy the implementation contract
     * see https://github.com/Analog-Labs/universal-factory/tree/main for mode details.
     */
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x0000000000001C4Bf962dF86e38F0c10c7972C6E);

    /**
     * @dev Bytecode hash of the Universal Factory, used to verify if the contract is deployed.
     */
    bytes32 internal constant FACTORY_CODEHASH = 0x0dac89b851eaa2369ef725788f1aa9e2094bc7819f5951e3eeaa28420f202b50;

    /**
     * @dev Hash of the implementation contract creation code.
     */
    bytes32 internal constant IMPLEMENTATION_CODEHASH = keccak256(type(Gateway).creationCode);

    /**
     * @dev Salt of the implementation.
     */
    bytes32 internal constant IMPLEMENTATION_SALT = bytes32(uint256(0x010000000000));

    /**
     * @dev Proxy admin
     */
    address internal constant ADMIN_ACCOUNT = 0xB41440FF80e1083350c91B21DE1061e0920A75AD;
    
    /**
     * Information about the current state of the migration
     * @param forkId The network fork id, see: https://book.getfoundry.sh/forge/fork-testing#forking-cheatcodes
     * @param mortality The maximum block number where the migration can be executed.
     * @param proxyAddress The address of the proxy contract
     */
    struct State {
        uint256 forkId;
        uint64 mortality;
        address proxyAddress;
    }

    /**
     * @dev Maps the network id to its migration state
     */
    mapping(uint16 => State) public states;

    // Computes the EIP-712 domain separador
    function _computeDomainSeparator(uint256 networkId, address addr) private pure returns (bytes32) {
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

    /**
     * @dev Retrieve network info and verify if the deployer is the admin of the proxy contract.
     */
    function _getNetworkInfo(address proxyAddress, address deployer)
        private
        view
        returns (UpdateNetworkInfo memory info, NetworkID networkId, bool hasProxy)
    {
        // Check if the chain has a network id
        {
            bool exists;
            (exists, networkId) = NetworkIDHelpers.tryFromChainID(block.chainid);
            require(exists, string(bytes.concat(bytes("network id not found for chain "), bytes(vm.toString(block.chainid)))));
        }

        //////////////////////////////////////////////////
        // Verify if the proxy is deployed and is valid //
        //////////////////////////////////////////////////
        hasProxy = proxyAddress.code.length > 0;
        if (hasProxy) {
            require(proxyAddress.codehash == PROXY_CODEHASH, "invalid proxy codehash");
        } else {
            console.log("PROXY NOT DEPLOYED");
        }

        ////////////////////////////////////////////////
        // Verify if the UNIVERSAL FACORY is deployed //
        ////////////////////////////////////////////////
        require(address(FACTORY).code.length > 0, "universal factory not deployed");
        require(address(FACTORY).codehash == FACTORY_CODEHASH, "invalid universal factory codehash");

        /////////////////////////
        // Retrieve Chain Info //
        /////////////////////////

        // Allocate the network information
        info = UpdateNetworkInfo({
            networkId: networkId.asUint(),
            domainSeparator: bytes32(0),
            gasLimit: 0,
            relativeGasPrice: UFloatMath.ONE,
            baseFee: 0,
            mortality: 0
        });
        console.log("        NETWORK ID", info.networkId);

        // Print information about the proxy contract
        address admin = address(0);
        address implementation = address(0);
        if (hasProxy) {
            // Check if the gateway.networkId == info.networkId
            uint16 gatewayNetworkId = IGateway(proxyAddress).networkId();
            vm.assertEq(gatewayNetworkId, info.networkId, "network id mismatch");

            // Retrieve the proxy admin
            admin = address(uint160(uint256(vm.load(proxyAddress, ERC1967.ADMIN_SLOT))));
            console.log("       PROXY_ADMIN", admin);

            // Retrieve the current implementation
            implementation = address(uint160(uint256(vm.load(proxyAddress, ERC1967.IMPLEMENTATION_SLOT))));
            console.log("    IMPLEMENATTION", implementation);
        } else {
            console.log("        NETWORK ID", "N/A");
            console.log("       PROXY_ADMIN", "N/A");
            console.log("    IMPLEMENATTION", "N/A");
        }

        // Print information about the current network
        console.log("   GATEWAY BALANCE", proxyAddress.balance);
        console.log("  DEPLOYER BALANCE", deployer.balance);
        console.log("      LATEST BLOCK", block.number);
        console.log("   BLOCK GAS LIMIT", block.gaslimit);
        console.log("          CHAIN ID", block.chainid);
        console.log("         GAS PRICE", tx.gasprice);
        console.log("          BASE FEE", block.basefee, "\n");

        require(hasProxy == false || admin == deployer, "deployer is not the admin if this contract");
        require(block.gaslimit < uint64(type(int64).max), "block gas limit exceeds the limit of int64");
        require(block.gaslimit > 1_000_000, "block gas limit is too low");
        require(block.number < uint64(type(int64).max), "block number limit exceeds the limit of int64");
        require(block.number > 1_000_000, "block number is low, is this a local testnet?");

        // Update network information
        if (hasProxy) {
            info.domainSeparator = _computeDomainSeparator(info.networkId, proxyAddress);
        }
        info.gasLimit = uint64(block.gaslimit >> 1);
        info.relativeGasPrice = UFloatMath.ONE;
        info.baseFee = 0;
        info.mortality = uint64(block.number + 128);

        // Save migration state information
        // states[info.networkId] = State({forkId: forkId, mortality: info.mortality, proxyAddress: proxyAddress});
    }

    /**
     * @dev Script entry point, the following core will upgrade the gateway contract of all networks.
     */
    function run() external {
        // Retrieve the gateway proxy address
        address proxyAddress = vm.envOr("PROXY_ADDRESS", 0x000000007f56768dE3133034FA730a909003a165);
        console.log("            SENDER", msg.sender);
        console.log("     PROXY_ADDRESS", proxyAddress);
        console.log("     ADMIN ACCOUNT", ADMIN_ACCOUNT);

        // Iterate over all the RPC URLs, defined in the `foundry.toml` file
        string[2][] memory urls = vm.rpcUrls();
        uint256[] memory forks = new uint256[](urls.length);
        UpdateNetworkInfo[] memory networks = new UpdateNetworkInfo[](urls.length);
        uint256 needsProxy = 0;

        // Check the network information
        for (uint256 i = 0; i < urls.length; i++) {
            string[2] memory entry = urls[i];
            console.log("        BLOCKCHAIN", entry[0]);
            console.log("           RPC URL", entry[1]);
            forks[i] = vm.createSelectFork(entry[1]);
            bool hasProxy;
            NetworkID networkId;
            (networks[i], networkId, hasProxy) = _getNetworkInfo(proxyAddress, 0xB41440FF80e1083350c91B21DE1061e0920A75AD);
            needsProxy |= BranchlessMath.toUint(!hasProxy) << i;
            console.log("");
        }


        if (needsProxy == 0) {
            console.log("ALL NETWORKS PROXIES ALREADY DEPLOYED");
            return;
        }

        // Deploy Proxy
        address deployer = address(0);

        // Validate the proxy deployment account balance and nonce
        // Send funds to the deployer account if necessary.
        for (uint256 i = 0; i < forks.length; i++) {
            // Skip if this network already has a proxy
            if (needsProxy & (1 << i) == 0) {
                continue;
            }
            console.log("     -- BLOCKCHAIN", urls[i][0]);
            
            // Switch the network
            vm.selectFork(forks[i]);

            // Setup the proxy deployer account
            if (deployer == address(0)) {
                // Try the current sender first
                deployer = msg.sender;
                address contractAddr = vm.computeCreateAddress(deployer, vm.getNonce(deployer));

                // Ask for the deployer private key
                if (contractAddr != proxyAddress) {
                    deployer = vm.addr(vm.promptSecretUint("Please enter the deployer private key"));
                    uint256 nonce = vm.getNonce(deployer);
                    contractAddr = vm.computeCreateAddress(deployer, nonce);
                    console.log("    PROXY DEPLOYER", deployer);
                    console.log("  DEPLOYER BALANCE", deployer.balance);
                    console.log("    DEPLOYER NONCE", nonce);
                    console.log("             PROXY", contractAddr);
                }

                // Make sure the deployer is the correct account
                require(contractAddr == proxyAddress, "invalid proxy deployment account");
            } else {
                // Make sure the deployer has enough funds to deploy the proxy
                uint256 nonce = vm.getNonce(deployer);
                address contractAddr = vm.computeCreateAddress(deployer, nonce);
                console.log("    PROXY DEPLOYER", deployer);
                console.log("  DEPLOYER BALANCE", deployer.balance);
                console.log("    DEPLOYER NONCE", nonce);
                console.log("             PROXY", contractAddr);

                // Make sure the deployer nonce is correct
                require(contractAddr == proxyAddress, "invalid proxy deployment nonce");
            }
            
            // Send funds to the deployer account
            if (deployer.balance < MINIMAL_DEPLOYER_BALANCE) {
                require(deployer != msg.sender, "deployer has no funds");
                console.log("   FUNDING ACCOUNT", msg.sender);
                console.log("   FUNDING BALANCE", msg.sender.balance);
                console.log("     FUNDING NONCE", vm.getNonce(msg.sender));
                require(msg.sender.balance > MINIMAL_DEPLOYER_BALANCE, "insufficient funds");

                vm.startBroadcast(msg.sender);
                payable(deployer).transfer(MINIMAL_DEPLOYER_BALANCE);
                vm.stopBroadcast();
            }
            console.log("");
        }

        console.log(" --------------- DEPLOYING IMPLEMENTATION --------------- ");
        address[] memory implementations = new address[](forks.length);
        {
            bytes memory bytecode = type(Gateway).creationCode;
            console.log("         IMPL HASH", vm.toString(bytes32(keccak256(bytecode))), "\n");
            for (uint256 i = 0; i < forks.length; i++) {
                // Skip if this network already has a proxy
                if (needsProxy & (1 << i) == 0) {
                    continue;
                }
                UpdateNetworkInfo memory info = networks[i];
                // Switch the network
                vm.selectFork(forks[i]);

                // Print information about the current network
                console.log("     -- BLOCKCHAIN", urls[i][0]);
                console.log("          CHAIN ID", block.chainid);
                console.log("        NETWORK ID", info.networkId);
                console.log("      BLOCK NUMBER", block.number);
                vm.assertEq(NetworkIDHelpers.fromChainID(block.chainid).asUint(), info.networkId, "network id mismatch");

                // Check if the the implementation is already deployed.
                bytes memory initCode = bytes.concat(
                    bytecode,
                    abi.encode(uint16(info.networkId), address(proxyAddress))
                );
                address expectedAddr = FACTORY.computeCreate2Address(IMPLEMENTATION_SALT, initCode);
                console.log("          DEPLOYER", msg.sender);
                console.log("  DEPLOYER BALANCE", msg.sender.balance);
                console.log("  CONTRACT ADDRESS", expectedAddr);

                if (expectedAddr.code.length == 0) {
                    require(msg.sender != deployer, "implementation not deployed");
                    // Deploy the implementation contract
                    vm.startBroadcast(msg.sender);
                    address implementation = FACTORY.create2(IMPLEMENTATION_SALT, initCode);
                    vm.stopBroadcast();
                    vm.assertEq(expectedAddr, implementation, "implementation address mismatch");
                    console.log(" DEPLOYMENT STATUS", "Deployed");
                    implementations[i] = implementation;
                } else {
                    console.log(" DEPLOYMENT STATUS", "Skipped, already deployed");
                }
                console.log();
            }
        }
        

        console.log(" -------------------- DEPLOYING PROXY ------------------- ");
        for (uint256 i = 0; i < forks.length; i++) {
            // Skip if this network already has a proxy
            if (needsProxy & (1 << i) == 0) {
                continue;
            }
            // Switch the network
            vm.selectFork(forks[i]);

            UpdateNetworkInfo memory info = networks[i];
            console.log("     -- BLOCKCHAIN", urls[i][0]);
            console.log("          CHAIN ID", block.chainid);
            console.log("        NETWORK ID", info.networkId);
            console.log("      BLOCK NUMBER", block.number);
            vm.assertEq(NetworkIDHelpers.fromChainID(block.chainid).asUint(), info.networkId, "network id mismatch");
            
            address implementation = implementations[i];
            uint256 nonce = vm.getNonce(deployer);
            address proxyAddr = vm.computeCreateAddress(deployer, nonce);
            console.log("  DEPLOYER ACCOUNT", deployer);
            console.log("  DEPLOYER BALANCE", deployer.balance);
            console.log("    DEPLOYER NONCE", nonce);
            console.log("    IMPLEMENTATION", implementation);
            console.log("     PROXY ADDRESS", proxyAddr);
            require(proxyAddr.code.length == 0, "proxy already deployed");
            require(deployer.balance >= MINIMAL_DEPLOYER_BALANCE, "deployer insufficient funds");
            require(proxyAddr == proxyAddress, "wrong deployer nonce");
            require(implementation.code.length > 0, "implementation not found");

            // TODO: Load the shards from the network, currently only the admin can add the shards.
            TssKey[] memory shards = new TssKey[](0);
            Network[] memory allNetworks = new Network[](0);
            bytes memory initializer = abi.encodeCall(Gateway.initialize, (ADMIN_ACCOUNT, shards, allNetworks));

            vm.startBroadcast(deployer);
            address proxy = address(new GatewayProxy(implementation, initializer));
            vm.stopBroadcast();
            console.log("     PROXY ADDRESS", proxyAddr);
            console.log(" DEPLOYMENT STATUS", proxy == proxyAddr ? "Success" : "Address Mismatch");
            console.log("");
        }
    }
}
