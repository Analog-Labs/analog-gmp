// SPDX-License-Identifier: MIT
// Analog's Contracts (last updated v0.1.0) (test/Example.t.sol)

pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Gateway, GatewayEIP712} from "src/Gateway.sol";
import {IGateway} from "src/interfaces/IGateway.sol";
import {IGmpRecipient} from "src/interfaces/IGmpRecipient.sol";
import {IExecutor} from "src/interfaces/IExecutor.sol";
import {GmpMessage, UpdateKeysMessage, Signature, TssKey, PrimitivesEip712} from "src/Primitives.sol";
import {MockERC20} from "src/examples/MockERC20.sol";
import {TestUtils, SigningKey, VerifyingKey, SigningUtils} from "./TestUtils.sol";

// contract ExampleTest is Test {
//     using SigningUtils for SigningKey;
//     using SigningUtils for VerifyingKey;
//     using PrimitivesEip712 for GmpMessage;
//     using TestUtils for address;

//     function testSignature() external pure {
//         SigningKey memory sk = TestUtils.createSigner();
//         VerifyingKey memory vk = sk.pubkey;
//         (uint256 c, uint256 z) = sk.sign("hello world!", TestUtils.randomFromSeed(1));
//         assertTrue(vk.verify("hello world!", c, z), "invalid signature");
//     }

//     function testTssSignature() external {
//         // Step 1: Deploy the Gateway contract
//         SigningKey memory signer = TestUtils.createSigner();
//         TssKey[] memory keys = new TssKey[](1);
//         keys[0] = TssKey({yParity: signer.yParity() == 28 ? 1 : 0, xCoord: signer.pubkey.px});
//         Gateway gateway = new Gateway(1337, keys);

//         // Step 2: Deploy the GMP recipient contract
//         MockERC20 token = new MockERC20("Token A", "TKNA", address(gateway));

//         // Step 3: Deposit tokens to the GMP recipient contract
//         bytes32 source = TestUtils.source(address(token), true);
//         gateway.deposit{value: 1_000_000}(source, 0);

//         // Step 4: Execute GMP message
//         GmpMessage memory gmp = GmpMessage({
//             source: source,
//             srcNetwork: 0,
//             dest: address(token),
//             destNetwork: 1337,
//             gasLimit: 1000,
//             salt: 1,
//             data: abi.encode(uint256(1000))
//         });
//         bytes32 messageID = gmp.eip712TypedHash(gateway.DOMAIN_SEPARATOR());
//         (uint256 c, uint256 z) = signer.signPrehashed(messageID, TestUtils.randomFromSeed(1));
//         Signature memory sig = Signature({xCoord: signer.pubkey.px, e: c, s: z});
//         assertTrue(gateway.gmpInfo(messageID).status == 0, "GMP message already executed");
//         gateway.execute(sig, gmp);
//         assertTrue(gateway.gmpInfo(messageID).status == 1, "failed to execute GMP message");
//     }

//     // function testSignature() external pure {
//     // assertEq(challenge, z);

//     // Chain memory chainB =
//     //     Chain({name: "Chain B", chainId: 1338, chainAlias: "chain_b", rpcUrl: "http://localhost:8546"});

//     // setChain("chain_b", chainB);
//     // uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
//     // address deployer = vmSafe.addr(deployerPrivateKey);
//     // vm.startBroadcast(deployerPrivateKey);

//     // MockERC20 nft = new MockERC20("Token A", "TKNA");
//     // uint256 balance = nft.balanceOf(deployer);
//     // console.log("initial supply:", deployer, balance);

//     // vm.stopBroadcast();
//     // }
// }
