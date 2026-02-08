// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {CertificateNFT} from "src/CertificateNFT.sol";

contract DeployCertificateNFT is Script {
    function run() external returns (CertificateNFT certificateNFT) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        uint256 trustedSignerKey = vm.envUint("MINT_TRUSTED_SIGNER");
        address initialOwner = vm.envOr("CERTIFICATE_OWNER", vm.addr(deployerPrivateKey));
        string memory name = vm.envOr("CERTIFICATE_NAME", string("web3 Career Build Certificate"));
        string memory symbol = vm.envOr("CERTIFICATE_SYMBOL", string("WCBC"));
        address trustedSigner = vm.envOr("MINT_TRUSTED_SIGNER", vm.addr(trustedSignerKey));

        vm.startBroadcast(deployerPrivateKey);
        certificateNFT = new CertificateNFT(name, symbol, initialOwner, trustedSigner);
        vm.stopBroadcast();
    }
}
