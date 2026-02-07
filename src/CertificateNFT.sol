// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract CertificateNFT is ERC721, ERC721URIStorage, Ownable, EIP712 {
    struct MintAuthorization {
        address to;
        bytes32 certificateId;
        string tokenURI;
        uint256 nonce;
        uint256 deadline;
    }

    event Minted(address indexed to, uint256 indexed tokenId, bytes32 indexed certificateId);
    event TrustedSignerUpdated(address indexed previousSigner, address indexed newSigner);

    error InvalidTrustedSigner();
    error InvalidRecipient();
    error InvalidCertificateId();
    error CertificateMinted();
    error AuthorizationExpired();
    error InvalidNonce();
    error InvalidSignature();

    mapping(bytes32 => uint256) public certificateToTokenId;

    mapping(uint256 => bytes32) public tokenIdToCertificate;

    mapping(address => uint256) public nonces;

    address public trustedSigner;

    uint256 private _nextTokenId;

    bytes32 private constant MINT_AUTHORIZATION_TYPEHASH =
        keccak256("MintAuthorization(address to,bytes32 certificateId,string tokenURI,uint256 nonce,uint256 deadline)");

    constructor(
        string memory name_,
        string memory symbol_,
        address trustedSigner_
    ) ERC721(name_, symbol_) Ownable(msg.sender) EIP712(name_, "1") {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        trustedSigner = trustedSigner_;
        _nextTokenId = 1;
    }

    function setTrustedSigner(address trustedSigner_) external onlyOwner {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        address previousSigner = trustedSigner;
        trustedSigner = trustedSigner_;
        emit TrustedSignerUpdated(previousSigner, trustedSigner_);
    }

    function mintWithSig(MintAuthorization calldata auth, bytes calldata signature) external {
        if (auth.to != msg.sender) revert InvalidRecipient();
        if (auth.certificateId == bytes32(0)) revert InvalidCertificateId();
        if (certificateToTokenId[auth.certificateId] != 0) revert CertificateMinted();
        if (block.timestamp > auth.deadline) revert AuthorizationExpired();
        if (auth.nonce != nonces[auth.to]) revert InvalidNonce();

        bytes32 digest = _hashTypedDataV4(_hashMintAuthorization(auth));
        address recoveredSigner = ECDSA.recover(digest, signature);
        if (recoveredSigner != trustedSigner) revert InvalidSignature();

        uint256 tokenId = _nextTokenId;
        unchecked {
            _nextTokenId = tokenId + 1;
        }

        unchecked {
            nonces[auth.to] = auth.nonce + 1;
        }
        certificateToTokenId[auth.certificateId] = tokenId;
        tokenIdToCertificate[tokenId] = auth.certificateId;

        _safeMint(auth.to, tokenId);
        _setTokenURI(tokenId, auth.tokenURI);

        emit Minted(auth.to, tokenId, auth.certificateId);
    }

    function isMinted(bytes32 certificateId) external view returns (bool) {
        return certificateToTokenId[certificateId] != 0;
    }

    function totalSupply() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    function tokenURI(uint256 tokenId) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721URIStorage) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function hashMintAuthorization(MintAuthorization calldata auth) external view returns (bytes32) {
        return _hashTypedDataV4(_hashMintAuthorization(auth));
    }

    function _hashMintAuthorization(MintAuthorization calldata auth) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    MINT_AUTHORIZATION_TYPEHASH,
                    auth.to,
                    auth.certificateId,
                    keccak256(bytes(auth.tokenURI)),
                    auth.nonce,
                    auth.deadline
                )
            );
    }
}
