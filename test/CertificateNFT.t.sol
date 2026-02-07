// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CertificateNFT} from "src/CertificateNFT.sol";

contract CertificateNFTTest is Test {
    CertificateNFT internal certificate;

    address internal user = address(0xB0B);

    function setUp() public {
        certificate = new CertificateNFT("Web3 Certificate", "W3CERT");
    }

    function test_Mint() public {
        bytes32 certId = keccak256("cert-001");

        vm.prank(user);
        certificate.mint(certId, "ipfs://certificate/1.json");

        assertEq(certificate.ownerOf(1), user);
        assertEq(certificate.tokenURI(1), "ipfs://certificate/1.json");
        assertEq(certificate.certificateToTokenId(certId), 1);
        assertEq(certificate.tokenIdToCertificate(1), certId);
        assertEq(certificate.totalSupply(), 1);
        assertTrue(certificate.isMinted(certId));
    }

    function test_RevertWhen_MintWithZeroCertificateId() public {
        vm.prank(user);
        vm.expectRevert(bytes("INVALID_CERTIFICATE_ID"));
        certificate.mint(bytes32(0), "ipfs://certificate/1.json");
    }

    function test_RevertWhen_MintDuplicateCertificate() public {
        bytes32 certId = keccak256("cert-001");

        vm.startPrank(user);
        certificate.mint(certId, "ipfs://certificate/1.json");

        vm.expectRevert(bytes("CERTIFICATE_MINTED"));
        certificate.mint(certId, "ipfs://certificate/2.json");
        vm.stopPrank();
    }
}
