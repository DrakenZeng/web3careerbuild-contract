// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BadgeNFT} from "src/BadgeNFT.sol";

contract ReentrantBadgeMinter {
    BadgeNFT internal immutable badge;
    BadgeNFT.MintAuthorization internal auth;
    bytes internal signature;
    bool internal attempted;
    bool public reenterFailed;

    constructor(BadgeNFT badge_) {
        badge = badge_;
    }

    function claim(BadgeNFT.MintAuthorization memory auth_, bytes memory signature_) external {
        auth = auth_;
        signature = signature_;
        badge.mintWithSig(auth_, signature_);
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4) {
        if (!attempted) {
            attempted = true;
            try badge.mintWithSig(auth, signature) {
                reenterFailed = false;
            } catch {
                reenterFailed = true;
            }
        }
        return this.onERC1155Received.selector;
    }
}

contract BadgeNFTTest is Test {
    BadgeNFT internal badge;

    address internal owner = address(0xA11CE);
    address internal user = address(0xB0B);
    uint256 internal signerPk;
    address internal signer;
    uint256 internal attackerPk;

    function setUp() public {
        signerPk = 0xA11CE123;
        signer = vm.addr(signerPk);
        attackerPk = 0xBAD123;
        vm.prank(owner);
        badge = new BadgeNFT("ipfs://default/{id}.json", owner, signer);
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

    function test_MintWithSig() public {
        vm.startPrank(owner);
        uint256 badgeTypeId = badge.createBadgeType("Bug Hunter", "ipfs://badge/bug-hunter.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType("award-001"), badgeTypeId);
        assertTrue(badge.isMinted("award-001"));
        assertEq(badge.nonces(user), 1);
    }

    function test_RevertWhen_MintWithDuplicateAwardId() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Mentor", "ipfs://badge/mentor.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 1, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature1 = _sign(auth1, signerPk);
        bytes memory signature2 = _sign(auth2, signerPk);

        vm.startPrank(user);
        badge.mintWithSig(auth1, signature1);

        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyMinted.selector, "award-001"));
        badge.mintWithSig(auth2, signature2);
        vm.stopPrank();
    }

    function test_RevertWhen_MintWithInvalidBadgeType() public {
        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: 999, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.InvalidBadgeType.selector, 999));
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_ExpiredAuthorization() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp - 1
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.AuthorizationExpired.selector);
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_NonceReused() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-002", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature1 = _sign(auth1, signerPk);
        bytes memory signature2 = _sign(auth2, signerPk);

        vm.startPrank(user);
        badge.mintWithSig(auth1, signature1);
        vm.expectRevert(BadgeNFT.InvalidNonce.selector);
        badge.mintWithSig(auth2, signature2);
        vm.stopPrank();
    }

    function test_MintWithOutOfOrderNonces() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-002", nonce: 2, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 1, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature2 = _sign(auth2, signerPk);
        bytes memory signature1 = _sign(auth1, signerPk);

        vm.startPrank(user);
        badge.mintWithSig(auth2, signature2);
        badge.mintWithSig(auth1, signature1);
        vm.stopPrank();

        assertEq(badge.nonces(user), 3);
    }

    function test_ReentrancyCannotMintDuplicate() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        ReentrantBadgeMinter minter = new ReentrantBadgeMinter(badge);
        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: address(minter),
            badgeTypeId: badgeTypeId,
            awardId: "award-reentrant",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        minter.claim(auth, signature);

        assertEq(badge.balanceOf(address(minter), badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType("award-reentrant"), badgeTypeId);
        assertEq(badge.nonces(address(minter)), 1);
        assertTrue(minter.reenterFailed());
    }

    function test_RevertWhen_InvalidSignature() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, attackerPk);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.InvalidSignature.selector);
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_ToNotCaller() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: address(0xCAFE),
            badgeTypeId: badgeTypeId,
            awardId: "award-001",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.InvalidRecipient.selector);
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_EmptyAwardId() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "", nonce: 0, deadline: block.timestamp + 10 minutes
        });

        vm.prank(user);
        vm.expectRevert(BadgeNFT.InvalidAwardId.selector);
        badge.mintWithSig(auth, "");
    }

    function test_SetTrustedSigner() public {
        address newSigner = vm.addr(0x1234);
        vm.prank(owner);
        badge.setTrustedSigner(newSigner);
        assertEq(badge.trustedSigner(), newSigner);
    }

    function test_RevertWhen_SetTrustedSignerByNonOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        badge.setTrustedSigner(vm.addr(0x1234));
    }

    function test_RevertWhen_TransferBadge() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.NonTransferable.selector);
        badge.safeTransferFrom(user, address(0xCAFE), badgeTypeId, 1, "");
    }

    function test_AdminTransferBadge() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(owner);
        badge.adminTransfer(user, address(0xCAFE), "award-001", "support-migration-1");

        assertEq(badge.balanceOf(user, badgeTypeId), 0);
        assertEq(badge.balanceOf(address(0xCAFE), badgeTypeId), 1);
        assertEq(badge.awardOwner("award-001"), address(0xCAFE));
    }

    function test_RevertWhen_AdminTransferByNonOwner() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        badge.adminTransfer(user, address(0xCAFE), "award-001", "support-migration-1");
    }

    function test_RevertWhen_AdminTransferWithWrongFrom() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(owner);
        vm.expectRevert(BadgeNFT.AwardOwnerMismatch.selector);
        badge.adminTransfer(address(0xDEAD), address(0xCAFE), "award-001", "support-migration-1");
    }

    function test_RevokeAward() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(owner);
        badge.revokeAward("award-001", "invalid");

        assertTrue(badge.isRevoked("award-001"));
    }

    function test_RevertWhen_RevokeAwardNotMinted() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardNotMinted.selector, "award-001"));
        badge.revokeAward("award-001", "invalid");
    }

    function test_RevertWhen_RevokeAwardTwice() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(owner);
        badge.revokeAward("award-001", "invalid");

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardRevoked.selector, "award-001"));
        badge.revokeAward("award-001", "invalid");
    }

    function test_RevertWhen_AdminTransferRevokedAward() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(owner);
        badge.revokeAward("award-001", "invalid");

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardRevoked.selector, "award-001"));
        badge.adminTransfer(user, address(0xCAFE), "award-001", "support-migration-1");
    }

    function test_RevertWhen_InvalidAwardIdFormat() public {
        uint256 badgeTypeId;
        vm.startPrank(owner);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.stopPrank();

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardId: "Award-001", nonce: 0, deadline: block.timestamp + 10 minutes
        });

        vm.prank(user);
        vm.expectRevert(BadgeNFT.InvalidAwardIdFormat.selector);
        badge.mintWithSig(auth, "");
    }

    function test_FreezeBadgeURI() public {
        vm.startPrank(owner);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        badge.freezeBadgeURI(badgeTypeId);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.BadgeTypeMetadataFrozen.selector, badgeTypeId));
        badge.setBadgeURI(badgeTypeId, "ipfs://badge/new.json");
        vm.stopPrank();
    }

    function test_FreezeDefaultURI() public {
        vm.prank(owner);
        badge.freezeDefaultURI();

        vm.prank(owner);
        vm.expectRevert(BadgeNFT.MetadataFrozen.selector);
        badge.setDefaultURI("ipfs://new-default/{id}.json");
    }

    function _sign(BadgeNFT.MintAuthorization memory auth, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 digest = badge.hashMintAuthorization(auth);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
