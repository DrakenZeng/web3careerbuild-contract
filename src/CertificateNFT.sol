// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

contract CertificateNFT is ERC721, Ownable, EIP712 {
    struct MintAuthorization {
        address to;
        bytes32 certificateId;
        uint256 nonce;
        uint256 deadline;
    }

    event Minted(address indexed to, uint256 indexed tokenId, bytes32 indexed certificateId);
    event TrustedSignerUpdated(address indexed previousSigner, address indexed newSigner);
    event CertificateRevoked(bytes32 indexed certificateId, uint256 indexed tokenId, string reason);
    event AdminTransfer(
        address indexed operator, address indexed from, address indexed to, uint256 tokenId, string requestId
    );

    error InvalidTrustedSigner();
    error InvalidRecipient();
    error InvalidAddress();
    error InvalidCertificateId();
    error CertificateNotMinted();
    error CertificateAlreadyRevoked();
    error CertificateMinted();
    error AuthorizationExpired();
    error InvalidNonce();
    error InvalidSignature();
    error NonTransferable();

    mapping(bytes32 => uint256) public certificateToTokenId;

    mapping(uint256 => bytes32) public tokenIdToCertificate;

    mapping(address => mapping(uint256 => bool)) public usedNonces;
    mapping(bytes32 => bool) public revokedCertificates;

    address public trustedSigner;
    string private _certificateBaseURI;

    uint256 private _nextTokenId;

    bytes32 private constant MINT_AUTHORIZATION_TYPEHASH =
        keccak256("MintAuthorization(address to,bytes32 certificateId,uint256 nonce,uint256 deadline)");

    constructor(
        string memory name_,
        string memory symbol_,
        string memory certificateBaseURI_,
        address initialOwner,
        address trustedSigner_
    )
        ERC721(name_, symbol_)
        Ownable(initialOwner)
        EIP712(name_, "1")
    {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        trustedSigner = trustedSigner_;
        _certificateBaseURI = certificateBaseURI_;
        _nextTokenId = 1;
    }

    function setTrustedSigner(address trustedSigner_) external onlyOwner {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        address previousSigner = trustedSigner;
        trustedSigner = trustedSigner_;
        emit TrustedSignerUpdated(previousSigner, trustedSigner_);
    }

    function mintWithSig(MintAuthorization calldata auth, bytes calldata signature) external {
        address to = auth.to;
        bytes32 certificateId = auth.certificateId;
        uint256 nonce = auth.nonce;
        uint256 deadline = auth.deadline;

        if (to != msg.sender) revert InvalidRecipient();
        if (certificateId == bytes32(0)) revert InvalidCertificateId();
        if (certificateToTokenId[certificateId] != 0) revert CertificateMinted();
        if (block.timestamp > deadline) revert AuthorizationExpired();
        if (usedNonces[to][nonce]) revert InvalidNonce();

        bytes32 digest = _hashTypedDataV4(_hashMintAuthorization(to, certificateId, nonce, deadline));
        address recoveredSigner = ECDSA.recoverCalldata(digest, signature);
        if (recoveredSigner != trustedSigner) revert InvalidSignature();

        uint256 tokenId = _nextTokenId;
        unchecked {
            _nextTokenId = tokenId + 1;
        }

        usedNonces[to][nonce] = true;
        certificateToTokenId[certificateId] = tokenId;
        tokenIdToCertificate[tokenId] = certificateId;

        _safeMint(to, tokenId);

        emit Minted(to, tokenId, certificateId);
    }

    function revokeCertificate(bytes32 certificateId, string calldata reason) external onlyOwner {
        if (certificateId == bytes32(0)) revert InvalidCertificateId();
        uint256 tokenId = certificateToTokenId[certificateId];
        if (tokenId == 0) revert CertificateNotMinted();
        if (revokedCertificates[certificateId]) revert CertificateAlreadyRevoked();

        revokedCertificates[certificateId] = true;
        emit CertificateRevoked(certificateId, tokenId, reason);
    }

    function isRevoked(bytes32 certificateId) external view returns (bool) {
        return revokedCertificates[certificateId];
    }

    function adminTransfer(address from, address to, uint256 tokenId, string calldata requestId) external onlyOwner {
        if (from == address(0) || to == address(0)) revert InvalidAddress();
        bytes32 certificateId = tokenIdToCertificate[tokenId];
        if (revokedCertificates[certificateId]) revert CertificateAlreadyRevoked();
        _safeTransfer(from, to, tokenId, "");
        emit AdminTransfer(msg.sender, from, to, tokenId, requestId);
    }

    function isMinted(bytes32 certificateId) external view returns (bool) {
        return certificateToTokenId[certificateId] != 0;
    }

    function totalSupply() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    function certificateBaseURI() external view returns (string memory) {
        return _certificateBaseURI;
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        return string.concat(_certificateBaseURI, Strings.toHexString(uint256(tokenIdToCertificate[tokenId]), 32));
    }

    function hashMintAuthorization(MintAuthorization calldata auth) external view returns (bytes32) {
        return _hashTypedDataV4(_hashMintAuthorization(auth.to, auth.certificateId, auth.nonce, auth.deadline));
    }

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0) && revokedCertificates[tokenIdToCertificate[tokenId]]) {
            revert CertificateAlreadyRevoked();
        }
        if (from != address(0) && to != address(0) && _msgSender() != owner()) {
            revert NonTransferable();
        }
        return super._update(to, tokenId, auth);
    }

    function _hashMintAuthorization(
        address to,
        bytes32 certificateId,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(MINT_AUTHORIZATION_TYPEHASH, to, certificateId, nonce, deadline));
    }
}
