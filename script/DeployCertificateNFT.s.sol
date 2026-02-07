// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {CertificateNFT} from "src/CertificateNFT.sol";

contract DeployCertificateNFT is Script {
    function run() external returns (CertificateNFT certificateNFT) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory name = vm.envOr("CERTIFICATE_NAME", string("web3 Career Build Certificate"));
        string memory symbol = vm.envOr("CERTIFICATE_SYMBOL", string("WCBC"));

        vm.startBroadcast(deployerPrivateKey);
        certificateNFT = new CertificateNFT(name, symbol);
        vm.stopBroadcast();
    }
}
