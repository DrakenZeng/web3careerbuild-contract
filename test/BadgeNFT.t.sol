// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
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
    address internal operator = address(0x0DE8A708);
    address internal user = address(0xB0B);
    uint256 internal signerPk;
    address internal signer;
    uint256 internal attackerPk;

    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 internal constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        signerPk = 0xA11CE123;
        signer = vm.addr(signerPk);
        attackerPk = 0xBAD123;
        vm.prank(owner);
        badge = new BadgeNFT("ipfs://default/{id}.json", owner, signer);

        vm.prank(owner);
        badge.grantRole(OPERATOR_ROLE, operator);
    }

    function test_RevertWhen_InitialOwnerZeroAddress() public {
        vm.expectRevert(BadgeNFT.InvalidAddress.selector);
        new BadgeNFT("ipfs://default/{id}.json", address(0), signer);
    }

    function test_CreateBadgeType() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Top Contributor", "ipfs://badge/top-contributor.json");

        assertEq(badgeTypeId, 1);
        assertEq(badge.totalBadgeTypes(), 1);
        assertEq(badge.uri(badgeTypeId), "ipfs://badge/top-contributor.json");
    }

    function test_RevertWhen_NonOperatorCreateBadgeType() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, OPERATOR_ROLE)
        );
        badge.createBadgeType("Top Contributor", "ipfs://badge/top-contributor.json");
    }

    function test_OperatorCanCreateBadgeType() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Operator Badge", "ipfs://badge/operator.json");

        assertEq(badgeTypeId, 1);
        assertEq(badge.uri(badgeTypeId), "ipfs://badge/operator.json");
    }

    function test_MintWithSig() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Bug Hunter", "ipfs://badge/bug-hunter.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType(_awardHash("award-001")), badgeTypeId);
        assertTrue(badge.isMinted(_awardHash("award-001")));
        assertEq(badge.nonces(user), 1);
    }

    function test_AdminMint() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Admin Badge", "ipfs://badge/admin.json");

        vm.prank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-admin-001"));

        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType(_awardHash("award-admin-001")), badgeTypeId);
        assertEq(badge.awardOwner(_awardHash("award-admin-001")), user);
        assertTrue(badge.isMinted(_awardHash("award-admin-001")));
    }

    function test_RevertWhen_NonOperatorAdminMint() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Admin Badge", "ipfs://badge/admin.json");

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, OPERATOR_ROLE)
        );
        badge.adminMint(user, badgeTypeId, _awardHash("award-admin-001"));
    }

    function test_RevertWhen_AdminMintDuplicateAwardId() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Admin Badge", "ipfs://badge/admin.json");

        vm.startPrank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-admin-001"));

        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyMinted.selector, _awardHash("award-admin-001")));
        badge.adminMint(user, badgeTypeId, _awardHash("award-admin-001"));
        vm.stopPrank();
    }

    function test_RevertWhen_AdminMintInvalidBadgeType() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.InvalidBadgeType.selector, 999));
        badge.adminMint(user, 999, _awardHash("award-admin-001"));
    }

    function test_RevertWhen_AdminMintToZeroAddress() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Admin Badge", "ipfs://badge/admin.json");

        vm.prank(operator);
        vm.expectRevert(BadgeNFT.InvalidAddress.selector);
        badge.adminMint(address(0), badgeTypeId, _awardHash("award-admin-001"));
    }

    function test_RevertWhen_MintWithDuplicateAwardId() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Mentor", "ipfs://badge/mentor.json");

        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 1, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature1 = _sign(auth1, signerPk);
        bytes memory signature2 = _sign(auth2, signerPk);

        vm.startPrank(user);
        badge.mintWithSig(auth1, signature1);

        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyMinted.selector, _awardHash("award-001")));
        badge.mintWithSig(auth2, signature2);
        vm.stopPrank();
    }

    function test_RevertWhen_MintWithInvalidBadgeType() public {
        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: 999, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.InvalidBadgeType.selector, 999));
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_ExpiredAuthorization() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp - 1
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.AuthorizationExpired.selector);
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_NonceReused() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-002"), nonce: 0, deadline: block.timestamp + 10 minutes
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
        uint256 badgeTypeId1;
        uint256 badgeTypeId2;
        vm.prank(operator);
        badgeTypeId1 = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        vm.prank(operator);
        badgeTypeId2 = badge.createBadgeType("Mentor", "ipfs://badge/mentor.json");

        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId2, awardIdHash: _awardHash("award-002"), nonce: 2, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId1, awardIdHash: _awardHash("award-001"), nonce: 1, deadline: block.timestamp + 10 minutes
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
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        ReentrantBadgeMinter minter = new ReentrantBadgeMinter(badge);
        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: address(minter),
            badgeTypeId: badgeTypeId,
            awardIdHash: _awardHash("award-reentrant"),
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        minter.claim(auth, signature);

        assertEq(badge.balanceOf(address(minter), badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType(_awardHash("award-reentrant")), badgeTypeId);
        assertEq(badge.nonces(address(minter)), 1);
        assertTrue(minter.reenterFailed());
    }

    function test_RevertWhen_InvalidSignature() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, attackerPk);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.InvalidSignature.selector);
        badge.mintWithSig(auth, signature);
    }

    function test_RevertWhen_ToNotCaller() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: address(0xCAFE),
            badgeTypeId: badgeTypeId,
            awardIdHash: _awardHash("award-001"),
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.InvalidRecipient.selector);
        badge.mintWithSig(auth, signature);
    }

    function test_MintWithSig_AllowsEmptyStringHash() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash(""), nonce: 0, deadline: block.timestamp + 10 minutes
        });

        bytes memory signature = _sign(auth, signerPk);
        vm.prank(user);
        badge.mintWithSig(auth, signature);

        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType(_awardHash("")), badgeTypeId);
    }

    function test_SetTrustedSigner() public {
        address newSigner = vm.addr(0x1234);
        vm.prank(owner);
        badge.setTrustedSigner(newSigner);
        assertEq(badge.trustedSigner(), newSigner);
    }

    function test_RevertWhen_SetTrustedSignerByNonAdmin() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, DEFAULT_ADMIN_ROLE)
        );
        badge.setTrustedSigner(vm.addr(0x1234));
    }

    function test_RevertWhen_OperatorSetTrustedSigner() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, operator, DEFAULT_ADMIN_ROLE
            )
        );
        badge.setTrustedSigner(vm.addr(0x1234));
    }

    function test_RevertWhen_TransferBadge() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(user);
        vm.expectRevert(BadgeNFT.NonTransferable.selector);
        badge.safeTransferFrom(user, address(0xCAFE), badgeTypeId, 1, "");
    }

    function test_RevertWhen_OperatorCallsSafeTransferFrom() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.prank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-transfer-operator"));

        vm.prank(operator);
        vm.expectRevert(BadgeNFT.NonTransferable.selector);
        badge.safeTransferFrom(user, address(0xCAFE), badgeTypeId, 1, "");
    }

    function test_RevertWhen_AdminCallsSafeBatchTransferFrom() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.prank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-transfer-admin"));

        uint256[] memory ids = new uint256[](1);
        ids[0] = badgeTypeId;
        uint256[] memory values = new uint256[](1);
        values[0] = 1;

        vm.prank(owner);
        vm.expectRevert(BadgeNFT.NonTransferable.selector);
        badge.safeBatchTransferFrom(user, address(0xCAFE), ids, values, "");
    }

    function test_AdminTransferBadge() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(operator);
        badge.adminTransfer(user, address(0xCAFE), _awardHash("award-001"), "support-migration-1");

        assertEq(badge.balanceOf(user, badgeTypeId), 0);
        assertEq(badge.balanceOf(address(0xCAFE), badgeTypeId), 1);
        assertEq(badge.awardOwner(_awardHash("award-001")), address(0xCAFE));
    }

    function test_RevertWhen_AdminTransferByNonOperator() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, OPERATOR_ROLE)
        );
        badge.adminTransfer(user, address(0xCAFE), _awardHash("award-001"), "support-migration-1");
    }

    function test_RevertWhen_AdminTransferWithWrongFrom() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(operator);
        vm.expectRevert(BadgeNFT.AwardOwnerMismatch.selector);
        badge.adminTransfer(address(0xDEAD), address(0xCAFE), _awardHash("award-001"), "support-migration-1");
    }

    function test_RevokeAward() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(operator);
        badge.revokeAward(_awardHash("award-001"), "invalid");

        assertTrue(badge.isRevoked(_awardHash("award-001")));
    }

    function test_OperatorCanRevokeAward() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.prank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-op-001"));

        vm.prank(operator);
        badge.revokeAward(_awardHash("award-op-001"), "policy violation");

        assertTrue(badge.isRevoked(_awardHash("award-op-001")));
    }

    function test_OperatorCanAdminTransfer() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.prank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-op-002"));

        vm.prank(operator);
        badge.adminTransfer(user, address(0xCAFE), _awardHash("award-op-002"), "migration-001");

        assertEq(badge.balanceOf(user, badgeTypeId), 0);
        assertEq(badge.balanceOf(address(0xCAFE), badgeTypeId), 1);
        assertEq(badge.awardOwner(_awardHash("award-op-002")), address(0xCAFE));
    }

    function test_RevertWhen_AdminTransferRecipientAlreadyOwnsBadgeType() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        address recipient = address(0xCAFE);
        vm.startPrank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-transfer-001"));
        badge.adminMint(recipient, badgeTypeId, _awardHash("award-transfer-002"));
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyOwnsBadgeType.selector, recipient, badgeTypeId));
        badge.adminTransfer(user, recipient, _awardHash("award-transfer-001"), "support-migration-1");
        vm.stopPrank();
    }

    function test_RevertWhen_RevokeAwardNotMinted() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardNotMinted.selector, _awardHash("award-001")));
        badge.revokeAward(_awardHash("award-001"), "invalid");
    }

    function test_RevertWhen_RevokeAwardTwice() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(operator);
        badge.revokeAward(_awardHash("award-001"), "invalid");

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardRevoked.selector, _awardHash("award-001")));
        badge.revokeAward(_awardHash("award-001"), "invalid");
    }

    function test_ReinstateAwardSameOwner() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.startPrank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-reinstate-001"));
        badge.revokeAward(_awardHash("award-reinstate-001"), "invalid");
        badge.reinstateAward(user, _awardHash("award-reinstate-001"), "appeal approved", "reinstate-001");
        vm.stopPrank();

        assertFalse(badge.isRevoked(_awardHash("award-reinstate-001")));
        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardOwner(_awardHash("award-reinstate-001")), user);
    }

    function test_ReinstateAwardWithTransferToNewOwner() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        address newOwner = address(0xCAFE);

        vm.startPrank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-reinstate-002"));
        badge.revokeAward(_awardHash("award-reinstate-002"), "invalid");
        badge.reinstateAward(newOwner, _awardHash("award-reinstate-002"), "manual reassignment", "reinstate-002");
        vm.stopPrank();

        assertFalse(badge.isRevoked(_awardHash("award-reinstate-002")));
        assertEq(badge.balanceOf(user, badgeTypeId), 0);
        assertEq(badge.balanceOf(newOwner, badgeTypeId), 1);
        assertEq(badge.awardOwner(_awardHash("award-reinstate-002")), newOwner);
    }

    function test_RevertWhen_ReinstateAwardNotRevoked() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.prank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-reinstate-003"));

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardNotRevoked.selector, _awardHash("award-reinstate-003")));
        badge.reinstateAward(user, _awardHash("award-reinstate-003"), "noop", "reinstate-003");
    }

    function test_RevertWhen_ReinstateAwardRecipientAlreadyOwnsBadgeType() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");
        address recipient = address(0xCAFE);

        vm.startPrank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-reinstate-004"));
        badge.adminMint(recipient, badgeTypeId, _awardHash("award-reinstate-005"));
        badge.revokeAward(_awardHash("award-reinstate-004"), "invalid");
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyOwnsBadgeType.selector, recipient, badgeTypeId));
        badge.reinstateAward(recipient, _awardHash("award-reinstate-004"), "manual reassignment", "reinstate-004");
        vm.stopPrank();
    }

    function test_RevertWhen_AdminTransferRevokedAward() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        badge.mintWithSig(auth, signature);

        vm.prank(operator);
        badge.revokeAward(_awardHash("award-001"), "invalid");

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AwardRevoked.selector, _awardHash("award-001")));
        badge.adminTransfer(user, address(0xCAFE), _awardHash("award-001"), "support-migration-1");
    }

    function test_MintWithSig_AwardHashIsOpaque() public {
        uint256 badgeTypeId;
        vm.prank(operator);
        badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("Award-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });

        bytes memory signature = _sign(auth, signerPk);
        vm.prank(user);
        badge.mintWithSig(auth, signature);

        assertEq(badge.balanceOf(user, badgeTypeId), 1);
        assertEq(badge.awardIdToBadgeType(_awardHash("Award-001")), badgeTypeId);
    }

    function test_RevertWhen_MintWithSigRecipientAlreadyOwnsBadgeType() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        BadgeNFT.MintAuthorization memory auth1 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-owned-001"), nonce: 0, deadline: block.timestamp + 10 minutes
        });
        BadgeNFT.MintAuthorization memory auth2 = BadgeNFT.MintAuthorization({
            to: user, badgeTypeId: badgeTypeId, awardIdHash: _awardHash("award-owned-002"), nonce: 1, deadline: block.timestamp + 10 minutes
        });

        vm.startPrank(user);
        bytes memory sig1 = _sign(auth1, signerPk);
        bytes memory sig2 = _sign(auth2, signerPk);
        badge.mintWithSig(auth1, sig1);
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyOwnsBadgeType.selector, user, badgeTypeId));
        badge.mintWithSig(auth2, sig2);
        vm.stopPrank();
    }

    function test_RevertWhen_AdminMintRecipientAlreadyOwnsBadgeType() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.startPrank(operator);
        badge.adminMint(user, badgeTypeId, _awardHash("award-admin-owned-001"));
        vm.expectRevert(abi.encodeWithSelector(BadgeNFT.AlreadyOwnsBadgeType.selector, user, badgeTypeId));
        badge.adminMint(user, badgeTypeId, _awardHash("award-admin-owned-002"));
        vm.stopPrank();
    }

    function test_FreezeBadgeURI() public {
        vm.prank(operator);
        uint256 badgeTypeId = badge.createBadgeType("Builder", "ipfs://badge/builder.json");

        vm.startPrank(owner);
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

    function test_GrantAndRevokeOperatorRole() public {
        address newOperator = address(0xBEE);

        vm.prank(owner);
        badge.grantRole(OPERATOR_ROLE, newOperator);
        assertTrue(badge.hasRole(OPERATOR_ROLE, newOperator));

        vm.prank(owner);
        badge.revokeRole(OPERATOR_ROLE, newOperator);
        assertFalse(badge.hasRole(OPERATOR_ROLE, newOperator));
    }

    function _awardHash(string memory awardId) internal pure returns (bytes32) {
        return keccak256(bytes(awardId));
    }

    function _sign(BadgeNFT.MintAuthorization memory auth, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 digest = badge.hashMintAuthorization(auth);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
