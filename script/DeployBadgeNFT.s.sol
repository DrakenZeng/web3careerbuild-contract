// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {BadgeNFT} from "src/BadgeNFT.sol";

contract DeployBadgeNFT is Script {
    function run() external returns (BadgeNFT badgeNFT) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address initialOwner = vm.addr(deployerPrivateKey);
        string memory baseURI = vm.envOr("BADGE_BASE_URI", string("ipfs://badge-default/{id}.json"));

        vm.startBroadcast(deployerPrivateKey);
        badgeNFT = new BadgeNFT(baseURI, initialOwner);
        vm.stopBroadcast();
    }
}
