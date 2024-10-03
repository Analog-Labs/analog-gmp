// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Example.t.sol)

pragma solidity >=0.8.0;

import {IUniversalFactory} from "@universal-factory/IUniversalFactory.sol";
import {FactoryUtils} from "@universal-factory/FactoryUtils.sol";
import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {Random} from "./Random.sol";
import {MockERC20} from "./MockERC20.sol";
import {GmpTestTools} from "./GmpTestTools.sol";
import {TestUtils, SigningKey, VerifyingKey, SigningUtils} from "./TestUtils.sol";
import {Gateway, GatewayEIP712} from "../src/Gateway.sol";
import {GatewayProxy} from "../src/GatewayProxy.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IGmpReceiver} from "../src/interfaces/IGmpReceiver.sol";
import {IExecutor} from "../src/interfaces/IExecutor.sol";
import {
    GmpMessage,
    UpdateKeysMessage,
    Signature,
    TssKey,
    Network,
    GmpStatus,
    GmpSender,
    PrimitiveUtils
} from "../src/Primitives.sol";

contract ExampleTest is Test {
    using SigningUtils for SigningKey;
    using SigningUtils for VerifyingKey;
    using PrimitiveUtils for GmpMessage;
    using PrimitiveUtils for address;
    using FactoryUtils for IUniversalFactory;

    /**
     * @dev The address of the `UniversalFactory` contract, must be the same on all networks.
     */
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x0000000000001C4Bf962dF86e38F0c10c7972C6E);

    VmSafe.Wallet private _proxyAdmin;
    uint16 private constant SRC_NETWORK_ID = 1234;
    uint16 private constant DEST_NETWORK_ID = 1337;
    address private _sender;

    address private constant ALICE = address(bytes20(keccak256("Alice")));
    address private constant BOB = address(bytes20(keccak256("Bob")));

    constructor() {
        require(FACTORY == TestUtils.deployFactory(), "factory address mismatch");
        _proxyAdmin = vm.createWallet(vm.randomUint());
        vm.deal(_proxyAdmin.addr, 100 ether);
    }

    function setUp() external {
        vm.deal(ALICE, 100 ether);
        vm.deal(BOB, 100 ether);
    }

    function deployGateway(VerifyingKey memory pubkey, uint16[] memory networkIds)
        private
        returns (Network[] memory networks)
    {
        address deployer = _proxyAdmin.addr;
        VmSafe.CallerMode prevCallerMode;
        address prevMsgSender;
        address prevTxOrigin;
        (prevCallerMode, prevMsgSender, prevTxOrigin) =
            TestUtils.setCallerMode(VmSafe.CallerMode.RecurrentBroadcast, deployer, deployer);

        // bytes32 salt = bytes32(0);
        bytes memory proxyCreationCode = abi.encodePacked(type(GatewayProxy).creationCode, abi.encode(deployer));

        TssKey[] memory keys = new TssKey[](1);
        keys[0] = TssKey({yParity: pubkey.yParity() == 28 ? 1 : 0, xCoord: pubkey.px});

        networks = new Network[](networkIds.length);
        for (uint256 i = 0; i < networks.length; i++) {
            Network memory network = networks[i];
            network.id = networkIds[i];
            // networks[i].gateway = vm.computeCreateAddress(_sender, vm.getNonce(_sender) + 1 + (i * 2));
            network.gateway = FACTORY.computeCreate2Address(bytes32(uint256(network.id)), proxyCreationCode);
        }

        bytes memory initializer = abi.encodeCall(Gateway.initialize, (deployer, keys, networks));
        for (uint256 i = 0; i < networks.length; i++) {
            Network memory network = networks[i];

            // 1 - Deploy implementation contract
            bytes memory implementationCreationCode =
                abi.encodePacked(type(Gateway).creationCode, abi.encode(network.gateway));
            address implementation =
                FACTORY.create2(bytes32(uint256(network.id)), implementationCreationCode, abi.encode(network.id));

            // 2 - Authorize the deployment
            bytes memory authorization;
            {
                bytes32 digest = keccak256(abi.encode(network.gateway, implementation));
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(_proxyAdmin, digest);
                authorization = abi.encode(v, r, s, implementation);
            }

            // address implementation = address(new Gateway(networks[i].id, networks[i].gateway));
            // address proxy = address(new GatewayProxy(implementation, initializer));
            // 3 - Deploy proxy contract
            address proxy = FACTORY.create2(bytes32(uint256(network.id)), proxyCreationCode, authorization, initializer);

            assertEq(proxy, network.gateway, "GatewayProxy address mismatch");
            vm.deal(proxy, 100 ether);
        }

        TestUtils.setCallerMode(prevCallerMode, prevMsgSender, prevTxOrigin);
    }

    function testSignature() external pure {
        SigningKey memory sk = TestUtils.createSigner();
        VerifyingKey memory vk = sk.pubkey;
        (uint256 c, uint256 z) = sk.sign("hello world!", Random.nextUint());
        assertTrue(vk.verify("hello world!", c, z), "invalid signature");
    }

    function testTeleportTokens() external {
        vm.txGasPrice(1);
        _sender = TestUtils.createTestAccount(100 ether);
        vm.startPrank(_sender, _sender);

        // Step 1: Deploy the Gateway contract
        SigningKey memory signer = TestUtils.createSigner();
        Gateway srcGateway;
        Gateway dstGateway;
        {
            uint16[] memory networkIds = new uint16[](2);
            networkIds[0] = SRC_NETWORK_ID;
            networkIds[1] = DEST_NETWORK_ID;
            Network[] memory networks = deployGateway(signer.pubkey, networkIds);
            srcGateway = Gateway(networks[0].gateway);
            dstGateway = Gateway(networks[1].gateway);
        }
        if (msg.data.length == 4) {
            return;
        }

        // Step 2: Deploy the sender and recipient contracts
        MockERC20 srcToken = MockERC20(vm.computeCreateAddress(_sender, vm.getNonce(_sender) + 1));
        MockERC20 dstToken =
            new MockERC20("Destination Token", "B", dstGateway, srcToken, srcGateway.networkId(), ALICE, 0);
        srcToken = new MockERC20("Source Token", "A", srcGateway, dstToken, dstGateway.networkId(), ALICE, 1000);

        // Step 3: Send GMP message
        GmpSender source = address(srcToken).toSender(true);
        GmpMessage memory gmp = GmpMessage({
            source: source,
            srcNetwork: SRC_NETWORK_ID,
            dest: address(dstToken),
            destNetwork: DEST_NETWORK_ID,
            gasLimit: 100_000,
            salt: 0,
            data: abi.encode(MockERC20.CrossChainTransfer({from: ALICE, to: BOB, amount: 100}))
        });

        // Expect `GmpCreated` to be emitted
        bytes32 messageID = gmp.eip712TypedHash(dstGateway.DOMAIN_SEPARATOR());
        vm.expectEmit(true, true, true, true, address(srcGateway));
        emit IGateway.GmpCreated(
            messageID, GmpSender.unwrap(gmp.source), gmp.dest, gmp.destNetwork, gmp.gasLimit, gmp.salt, gmp.data
        );

        {
            // Estimate the cost of teleporting 100 tokens
            uint256 gmpCost = srcToken.teleportCost();

            // Submit the GMP message from `sender` contract
            vm.stopPrank();
            vm.prank(ALICE, ALICE);
            srcToken.teleport{value: gmpCost}(BOB, 100);
        }

        vm.startPrank(_sender, _sender);
        (uint256 c, uint256 z) = signer.signPrehashed(messageID, Random.nextUint());
        Signature memory sig = Signature({xCoord: signer.pubkey.px, e: c, s: z});
        assertTrue(dstGateway.gmpInfo(messageID).status == GmpStatus.NOT_FOUND, "GMP message already executed");

        // Expect `GmpExecuted` to be emitted
        vm.expectEmit(true, true, true, true, address(dstGateway));
        emit IExecutor.GmpExecuted(messageID, gmp.source, gmp.dest, GmpStatus.SUCCESS, messageID);

        // Execute the GMP message
        dstGateway.execute(sig, gmp);
        assertTrue(dstGateway.gmpInfo(messageID).status == GmpStatus.SUCCESS, "failed to execute GMP message");

        // Check balance
        assertEq(srcToken.balanceOf(ALICE), 900, "sender balance mismatch");
        assertEq(dstToken.balanceOf(ALICE), 0, "recipient balance mismatch");
        assertEq(srcToken.balanceOf(BOB), 0, "sender balance mismatch");
        assertEq(dstToken.balanceOf(BOB), 100, "recipient balance mismatch");
    }
}
