// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BadgeNFT} from "src/BadgeNFT.sol";

contract BadgeNFTTest is Test {
    BadgeNFT internal badge;

    address internal owner = address(0xA11CE);
    address internal user = address(0xB0B);

    function setUp() public {
        vm.prank(owner);
        badge = new BadgeNFT("ipfs://default/{id}.json", owner);
    }

    function test_CreateBadgeType() public {
        vm.prank(owner);
        uint256 badgeTypeId = badge.createBadgeType("Top Contributor", "ipfs://badge/top-contributor.json");

        assertEq(badgeTypeId, 1);
        assertEq(badge.totalBadgeTypes(), 1);
        assertEq(badge.uri(badgeTypeId), "ipfs://badge/top-contributor.json");
    }

    function test_RevertWhen_NonOwnerCreateBadgeType() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        badge.createBadgeType("Top Contributor", "ipfs://badge/top-contributor.json");
    }

    function test_Mint() public {
        vm.startPrank(owner);
        uint256 badgeTypeId = badge.createBadgeType("Bug Hunter", "ipfs://badge/bug-hunter.json");
        badge.mint(user, badgeTypeId, "award-001");
        vm.stopPrank();

        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType("award-001"), badgeTypeId);
        assertTrue(badge.isMinted("award-001"));
    }

    function test_RevertWhen_MintWithDuplicateAwardId() public {
        vm.startPrank(owner);
        uint256 badgeTypeId = badge.createBadgeType("Mentor", "ipfs://badge/mentor.json");
        badge.mint(user, badgeTypeId, "award-001");

        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyMinted.selector, "award-001"));
        badge.mint(user, badgeTypeId, "award-001");
        vm.stopPrank();
    }

    function test_RevertWhen_MintWithInvalidBadgeType() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.InvalidBadgeType.selector, 999));
        badge.mint(user, 999, "award-001");
    }

    function test_RevertWhen_TransferBadge() public {
        vm.startPrank(owner);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        badge.mint(user, badgeTypeId, "award-001");
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(bytes("BadgeNFT: non-transferable"));
        badge.safeTransferFrom(user, address(0xCAFE), badgeTypeId, 1, "");
    }
}
