// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {CertificateNFT} from "src/CertificateNFT.sol";

contract CertificateNFTTest is Test {
    CertificateNFT internal certificate;

    address internal owner = address(0xA11CE);
    address internal user = address(0xB0B);
    address internal user2 = address(0xCAFE);
    uint256 internal signerPk;
    address internal signer;
    uint256 internal attackerPk;

    function setUp() public {
        signerPk = 0xA11CE;
        signer = vm.addr(signerPk);
        attackerPk = 0xBAD;
        certificate = new CertificateNFT("Web3 Certificate", "W3CERT", owner, signer);
    }

    function test_MintWithSig() public {
        bytes32 certId = keccak256("cert-001");
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 10 minutes;
        string memory uri = "ipfs://certificate/1.json";
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user, certificateId: certId, tokenURI: uri, nonce: nonce, deadline: deadline
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        assertEq(certificate.ownerOf(1), user);
        assertEq(certificate.tokenURI(1), uri);
        assertEq(certificate.certificateToTokenId(certId), 1);
        assertEq(certificate.tokenIdToCertificate(1), certId);
        assertEq(certificate.nonces(user), 1);
        assertEq(certificate.totalSupply(), 1);
        assertTrue(certificate.isMinted(certId));
    }

    function test_RevertWhen_MintWithZeroCertificateId() public {
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: bytes32(0),
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(CertificateNFT.InvalidCertificateId.selector);
        certificate.mintWithSig(auth, signature);
    }

    function test_RevertWhen_MintDuplicateCertificate() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth1 = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        CertificateNFT.MintAuthorization memory auth2 = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/2.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature1 = _sign(auth1, signerPk);
        bytes memory signature2 = _sign(auth2, signerPk);

        vm.startPrank(user);
        certificate.mintWithSig(auth1, signature1);

        vm.expectRevert(CertificateNFT.CertificateMinted.selector);
        certificate.mintWithSig(auth2, signature2);
        vm.stopPrank();
    }

    function test_RevertWhen_ExpiredAuthorization() public {
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: keccak256("cert-001"),
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp - 1
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(CertificateNFT.AuthorizationExpired.selector);
        certificate.mintWithSig(auth, signature);
    }

    function test_RevertWhen_NonceReused() public {
        CertificateNFT.MintAuthorization memory auth1 = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: keccak256("cert-001"),
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        CertificateNFT.MintAuthorization memory auth2 = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: keccak256("cert-002"),
            tokenURI: "ipfs://certificate/2.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature1 = _sign(auth1, signerPk);
        bytes memory signature2 = _sign(auth2, signerPk);

        vm.startPrank(user);
        certificate.mintWithSig(auth1, signature1);
        vm.expectRevert(CertificateNFT.InvalidNonce.selector);
        certificate.mintWithSig(auth2, signature2);
        vm.stopPrank();
    }

    function test_MintWithOutOfOrderNonces() public {
        CertificateNFT.MintAuthorization memory auth2 = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: keccak256("cert-002"),
            tokenURI: "ipfs://certificate/2.json",
            nonce: 2,
            deadline: block.timestamp + 10 minutes
        });
        CertificateNFT.MintAuthorization memory auth1 = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: keccak256("cert-001"),
            tokenURI: "ipfs://certificate/1.json",
            nonce: 1,
            deadline: block.timestamp + 10 minutes
        });

        bytes memory signature2 = _sign(auth2, signerPk);
        bytes memory signature1 = _sign(auth1, signerPk);

        vm.startPrank(user);
        certificate.mintWithSig(auth2, signature2);
        certificate.mintWithSig(auth1, signature1);
        vm.stopPrank();

        assertEq(certificate.nonces(user), 3);
    }

    function test_RevertWhen_InvalidSignature() public {
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: keccak256("cert-001"),
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, attackerPk);

        vm.prank(user);
        vm.expectRevert(CertificateNFT.InvalidSignature.selector);
        certificate.mintWithSig(auth, signature);
    }

    function test_RevertWhen_ToNotCaller() public {
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: address(0xCAFE),
            certificateId: keccak256("cert-001"),
            tokenURI: "ipfs://certificate/1.json",
            nonce: 1,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        vm.expectRevert(CertificateNFT.InvalidRecipient.selector);
        certificate.mintWithSig(auth, signature);
    }

    function test_RevertWhen_UserTransfer() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        vm.prank(user);
        vm.expectRevert(CertificateNFT.NonTransferable.selector);
        certificate.transferFrom(user, user2, 1);
    }

    function test_AdminTransfer() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        vm.prank(owner);
        certificate.adminTransfer(user, user2, 1, "support-migration-1");

        assertEq(certificate.ownerOf(1), user2);
    }

    function test_RevertWhen_AdminTransferByNonOwner() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        certificate.adminTransfer(user, user2, 1, "support-migration-1");
    }

    function test_RevokeCertificate() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        vm.prank(owner);
        certificate.revokeCertificate(certId, "fraud");

        assertTrue(certificate.isRevoked(certId));
    }

    function test_RevertWhen_RevokeNonMintedCertificate() public {
        bytes32 certId = keccak256("cert-999");
        vm.prank(owner);
        vm.expectRevert(CertificateNFT.CertificateNotMinted.selector);
        certificate.revokeCertificate(certId, "invalid");
    }

    function test_RevertWhen_RevokeCertificateTwice() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        vm.prank(owner);
        certificate.revokeCertificate(certId, "fraud");

        vm.prank(owner);
        vm.expectRevert(CertificateNFT.CertificateAlreadyRevoked.selector);
        certificate.revokeCertificate(certId, "fraud-again");
    }

    function test_RevertWhen_AdminTransferRevokedCertificate() public {
        bytes32 certId = keccak256("cert-001");
        CertificateNFT.MintAuthorization memory auth = CertificateNFT.MintAuthorization({
            to: user,
            certificateId: certId,
            tokenURI: "ipfs://certificate/1.json",
            nonce: 0,
            deadline: block.timestamp + 10 minutes
        });
        bytes memory signature = _sign(auth, signerPk);

        vm.prank(user);
        certificate.mintWithSig(auth, signature);

        vm.prank(owner);
        certificate.revokeCertificate(certId, "fraud");

        vm.prank(owner);
        vm.expectRevert(CertificateNFT.CertificateAlreadyRevoked.selector);
        certificate.adminTransfer(user, user2, 1, "support-migration-1");
    }

    function test_SetTrustedSigner() public {
        address newSigner = vm.addr(0x1234);
        vm.prank(owner);
        certificate.setTrustedSigner(newSigner);
        assertEq(certificate.trustedSigner(), newSigner);
    }

    function test_RevertWhen_SetTrustedSignerByNonOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        certificate.setTrustedSigner(vm.addr(0x1234));
    }

    function _sign(CertificateNFT.MintAuthorization memory auth, uint256 privateKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = certificate.hashMintAuthorization(auth);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
