// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BadgeNFT is ERC1155, Ownable, EIP712 {
    uint256 private _nextBadgeTypeId;

    mapping(bytes32 => uint256) private _awardIdHashToBadgeType;
    mapping(bytes32 => address) private _awardIdHashToOwner;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(uint256 => bool)) public usedNonces;
    mapping(bytes32 => bool) private _revokedAwardIdHashes;

    mapping(uint256 => bool) public badgeURIFrozen;
    bool public defaultURIFrozen;

    struct BadgeType {
        string name;
        string uri;
        bool exists;
    }

    struct MintAuthorization {
        address to;
        uint256 badgeTypeId;
        string awardId;
        uint256 nonce;
        uint256 deadline;
    }

    mapping(uint256 => BadgeType) public badgeTypes;
    address public trustedSigner;

    event BadgeMinted(address indexed to, uint256 indexed badgeTypeId, string awardId);
    event BadgeTypeCreated(uint256 indexed badgeTypeId, string name, string uri);
    event TrustedSignerUpdated(address indexed previousSigner, address indexed newSigner);
    event BadgeRevoked(string indexed awardId, uint256 indexed badgeTypeId, string reason);
    event AdminTransfer(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 badgeTypeId,
        uint256 amount,
        string requestId
    );
    event BadgeURIFrozen(uint256 indexed badgeTypeId);
    event DefaultURIFrozen();

    error AlreadyMinted(string awardId);
    error InvalidAddress();
    error InvalidAwardId();
    error InvalidAwardIdFormat();
    error InvalidBadgeType(uint256 badgeTypeId);
    error AwardOwnerMismatch();
    error AwardNotMinted(string awardId);
    error AwardRevoked(string awardId);
    error MetadataFrozen();
    error BadgeTypeMetadataFrozen(uint256 badgeTypeId);
    error InvalidTrustedSigner();
    error InvalidRecipient();
    error AuthorizationExpired();
    error InvalidNonce();
    error InvalidSignature();
    error NonTransferable();

    bytes32 private constant MINT_AUTHORIZATION_TYPEHASH =
        keccak256("MintAuthorization(address to,uint256 badgeTypeId,string awardId,uint256 nonce,uint256 deadline)");

    constructor(string memory baseURI_, address initialOwner, address trustedSigner_)
        ERC1155(baseURI_)
        Ownable(initialOwner)
        EIP712("BadgeNFT", "1")
    {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        trustedSigner = trustedSigner_;
        _nextBadgeTypeId = 1;
    }

    function createBadgeType(string memory name, string memory badgeURI)
        external
        onlyOwner
        returns (uint256 badgeTypeId)
    {
        badgeTypeId = _nextBadgeTypeId;
        unchecked {
            _nextBadgeTypeId = badgeTypeId + 1;
        }
        badgeTypes[badgeTypeId] = BadgeType({name: name, uri: badgeURI, exists: true});
        emit BadgeTypeCreated(badgeTypeId, name, badgeURI);
    }

    function setTrustedSigner(address trustedSigner_) external onlyOwner {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        address previousSigner = trustedSigner;
        trustedSigner = trustedSigner_;
        emit TrustedSignerUpdated(previousSigner, trustedSigner_);
    }

    function mintWithSig(MintAuthorization calldata auth, bytes calldata signature) external {
        address to = auth.to;
        uint256 badgeTypeId = auth.badgeTypeId;
        string calldata awardId = auth.awardId;
        bytes32 awardIdHash = _awardIdHash(awardId);
        uint256 nonce = auth.nonce;

        if (to == address(0)) revert InvalidAddress();
        if (to != msg.sender) revert InvalidRecipient();
        if (!badgeTypes[badgeTypeId].exists) revert InvalidBadgeType(badgeTypeId);
        if (_awardIdHashToBadgeType[awardIdHash] != 0) revert AlreadyMinted(awardId);
        if (block.timestamp > auth.deadline) revert AuthorizationExpired();
        if (usedNonces[to][nonce]) revert InvalidNonce();

        bytes32 digest = _hashTypedDataV4(_hashMintAuthorization(to, badgeTypeId, awardIdHash, nonce, auth.deadline));
        address recoveredSigner = ECDSA.recoverCalldata(digest, signature);
        if (recoveredSigner != trustedSigner) revert InvalidSignature();

        // Commit replay/uniqueness state before external callback in `_mint`.
        usedNonces[to][nonce] = true;
        if (nonce >= nonces[to]) {
            unchecked {
                nonces[to] = nonce + 1;
            }
        }
        _awardIdHashToBadgeType[awardIdHash] = badgeTypeId;
        _awardIdHashToOwner[awardIdHash] = to;

        _mint(to, badgeTypeId, 1, "");

        emit BadgeMinted(to, badgeTypeId, awardId);
    }

    function uri(uint256 tokenId) public view override returns (string memory) {
        string memory badgeURI = badgeTypes[tokenId].uri;
        if (bytes(badgeURI).length > 0) {
            return badgeURI;
        }
        return super.uri(tokenId);
    }

    function setBadgeURI(uint256 badgeTypeId, string memory newURI) external onlyOwner {
        if (!badgeTypes[badgeTypeId].exists) revert InvalidBadgeType(badgeTypeId);
        if (defaultURIFrozen) revert MetadataFrozen();
        if (badgeURIFrozen[badgeTypeId]) revert BadgeTypeMetadataFrozen(badgeTypeId);
        badgeTypes[badgeTypeId].uri = newURI;
    }

    function setDefaultURI(string memory newURI) external onlyOwner {
        if (defaultURIFrozen) revert MetadataFrozen();
        _setURI(newURI);
    }

    function isMinted(string calldata awardId) external view returns (bool) {
        return _awardIdHashToBadgeType[_awardIdHash(awardId)] != 0;
    }

    function isRevoked(string calldata awardId) external view returns (bool) {
        return _revokedAwardIdHashes[_awardIdHash(awardId)];
    }

    function revokeAward(string calldata awardId, string calldata reason) external onlyOwner {
        bytes32 awardIdHash = _awardIdHash(awardId);
        uint256 badgeTypeId = _awardIdHashToBadgeType[awardIdHash];
        if (badgeTypeId == 0) revert AwardNotMinted(awardId);
        if (_revokedAwardIdHashes[awardIdHash]) revert AwardRevoked(awardId);
        _revokedAwardIdHashes[awardIdHash] = true;
        emit BadgeRevoked(awardId, badgeTypeId, reason);
    }

    function adminTransfer(address from, address to, string calldata awardId, string calldata requestId)
        external
        onlyOwner
    {
        if (from == address(0) || to == address(0)) revert InvalidAddress();
        bytes32 awardIdHash = _awardIdHash(awardId);
        uint256 badgeTypeId = _awardIdHashToBadgeType[awardIdHash];
        if (badgeTypeId == 0) revert AwardNotMinted(awardId);
        if (_revokedAwardIdHashes[awardIdHash]) revert AwardRevoked(awardId);
        if (_awardIdHashToOwner[awardIdHash] != from) revert AwardOwnerMismatch();

        _safeTransferFrom(from, to, badgeTypeId, 1, "");
        _awardIdHashToOwner[awardIdHash] = to;

        emit AdminTransfer(msg.sender, from, to, badgeTypeId, 1, requestId);
    }

    function freezeBadgeURI(uint256 badgeTypeId) external onlyOwner {
        if (!badgeTypes[badgeTypeId].exists) revert InvalidBadgeType(badgeTypeId);
        badgeURIFrozen[badgeTypeId] = true;
        emit BadgeURIFrozen(badgeTypeId);
    }

    function freezeDefaultURI() external onlyOwner {
        defaultURIFrozen = true;
        emit DefaultURIFrozen();
    }

    function totalBadgeTypes() external view returns (uint256) {
        return _nextBadgeTypeId - 1;
    }

    function hashMintAuthorization(MintAuthorization calldata auth) external view returns (bytes32) {
        return _hashTypedDataV4(
            _hashMintAuthorization(auth.to, auth.badgeTypeId, _awardIdHash(auth.awardId), auth.nonce, auth.deadline)
        );
    }

    function awardIdToBadgeType(string calldata awardId) external view returns (uint256) {
        return _awardIdHashToBadgeType[_awardIdHash(awardId)];
    }

    function awardOwner(string calldata awardId) external view returns (address) {
        return _awardIdHashToOwner[_awardIdHash(awardId)];
    }

    function revokedAwardIds(string calldata awardId) external view returns (bool) {
        return _revokedAwardIdHashes[_awardIdHash(awardId)];
    }

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal override {
        if (from != address(0) && to != address(0) && _msgSender() != owner()) {
            revert NonTransferable();
        }
        super._update(from, to, ids, values);
    }

    function _hashMintAuthorization(
        address to,
        uint256 badgeTypeId,
        bytes32 awardIdHash,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(MINT_AUTHORIZATION_TYPEHASH, to, badgeTypeId, awardIdHash, nonce, deadline));
    }

    function _awardIdHash(string calldata awardId) internal pure returns (bytes32) {
        bytes calldata raw = bytes(awardId);
        uint256 len = raw.length;
        if (len == 0) revert InvalidAwardId();

        for (uint256 i = 0; i < len; i++) {
            bytes1 c = raw[i];
            bool isLower = c >= 0x61 && c <= 0x7A;
            bool isDigit = c >= 0x30 && c <= 0x39;
            bool isHyphen = c == 0x2D;
            bool isUnderscore = c == 0x5F;
            if (!(isLower || isDigit || isHyphen || isUnderscore)) revert InvalidAwardIdFormat();
        }
        return keccak256(raw);
    }
}
