// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BadgeNFT is ERC1155, AccessControl, EIP712 {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    uint256 private _nextBadgeTypeId;

    struct AwardRecord {
        uint256 badgeTypeId;
        address owner;
        bool revoked;
    }

    mapping(bytes32 => AwardRecord) private _awards;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    mapping(uint256 => bool) public badgeURIFrozen;
    bool public defaultURIFrozen;

    struct BadgeType {
        string name;
        string uri;
    }

    struct MintAuthorization {
        address to;
        uint256 badgeTypeId;
        bytes32 awardIdHash;
        uint256 nonce;
        uint256 deadline;
    }

    mapping(uint256 => BadgeType) public badgeTypes;
    address public trustedSigner;

    event BadgeMinted(address indexed to, uint256 indexed badgeTypeId, bytes32 indexed awardIdHash);
    event BadgeTypeCreated(uint256 indexed badgeTypeId, string name, string uri);
    event TrustedSignerUpdated(address indexed previousSigner, address indexed newSigner);
    event BadgeRevoked(bytes32 indexed awardIdHash, uint256 indexed badgeTypeId, string reason);
    event BadgeReinstated(
        bytes32 indexed awardIdHash,
        uint256 indexed badgeTypeId,
        address indexed from,
        address to,
        string reason,
        string requestId
    );
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

    error AlreadyMinted(bytes32 awardIdHash);
    error InvalidAddress();
    error InvalidBadgeType(uint256 badgeTypeId);
    error AwardOwnerMismatch();
    error AwardNotMinted(bytes32 awardIdHash);
    error AwardRevoked(bytes32 awardIdHash);
    error MetadataFrozen();
    error BadgeTypeMetadataFrozen(uint256 badgeTypeId);
    error InvalidTrustedSigner();
    error InvalidRecipient();
    error AuthorizationExpired();
    error InvalidNonce();
    error InvalidSignature();
    error NonTransferable();
    error AlreadyOwnsBadgeType(address owner, uint256 badgeTypeId);
    error InvalidBalanceForAwardOwner(address owner, uint256 badgeTypeId, uint256 balance);
    error AwardNotRevoked(bytes32 awardIdHash);

    bytes32 private constant MINT_AUTHORIZATION_TYPEHASH =
        keccak256("MintAuthorization(address to,uint256 badgeTypeId,bytes32 awardIdHash,uint256 nonce,uint256 deadline)");

    constructor(string memory baseURI_, address initialOwner, address trustedSigner_)
        ERC1155(baseURI_)
        EIP712("BadgeNFT", "1")
    {
        if (initialOwner == address(0)) revert InvalidAddress();
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        trustedSigner = trustedSigner_;
        _nextBadgeTypeId = 1;
        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
        _grantRole(OPERATOR_ROLE, initialOwner);
    }

    function createBadgeType(string memory name, string memory badgeURI)
        external
        onlyRole(OPERATOR_ROLE)
        returns (uint256 badgeTypeId)
    {
        badgeTypeId = _nextBadgeTypeId;
        unchecked {
            _nextBadgeTypeId = badgeTypeId + 1;
        }
        badgeTypes[badgeTypeId] = BadgeType({name: name, uri: badgeURI});
        emit BadgeTypeCreated(badgeTypeId, name, badgeURI);
    }

    function setTrustedSigner(address trustedSigner_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (trustedSigner_ == address(0)) revert InvalidTrustedSigner();
        address previousSigner = trustedSigner;
        trustedSigner = trustedSigner_;
        emit TrustedSignerUpdated(previousSigner, trustedSigner_);
    }

    function mintWithSig(MintAuthorization calldata auth, bytes calldata signature) external {
        address to = auth.to;
        uint256 badgeTypeId = auth.badgeTypeId;
        bytes32 awardIdHash = auth.awardIdHash;
        uint256 nonce = auth.nonce;

        if (to == address(0)) revert InvalidAddress();
        if (to != msg.sender) revert InvalidRecipient();
        if (!_badgeTypeExists(badgeTypeId)) revert InvalidBadgeType(badgeTypeId);
        if (_awards[awardIdHash].badgeTypeId != 0) revert AlreadyMinted(awardIdHash);
        if (block.timestamp > auth.deadline) revert AuthorizationExpired();
        if (usedNonces[to][nonce]) revert InvalidNonce();
        if (balanceOf(to, badgeTypeId) != 0) revert AlreadyOwnsBadgeType(to, badgeTypeId);

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
        _awards[awardIdHash] = AwardRecord({badgeTypeId: badgeTypeId, owner: to, revoked: false});

        _mint(to, badgeTypeId, 1, "");

        emit BadgeMinted(to, badgeTypeId, awardIdHash);
    }

    function adminMint(address to, uint256 badgeTypeId, bytes32 awardIdHash)
        external
        onlyRole(OPERATOR_ROLE)
    {
        if (to == address(0)) revert InvalidAddress();
        if (!_badgeTypeExists(badgeTypeId)) revert InvalidBadgeType(badgeTypeId);
        if (_awards[awardIdHash].badgeTypeId != 0) revert AlreadyMinted(awardIdHash);
        if (balanceOf(to, badgeTypeId) != 0) revert AlreadyOwnsBadgeType(to, badgeTypeId);

        _awards[awardIdHash] = AwardRecord({badgeTypeId: badgeTypeId, owner: to, revoked: false});

        _mint(to, badgeTypeId, 1, "");
        emit BadgeMinted(to, badgeTypeId, awardIdHash);
    }

    function uri(uint256 tokenId) public view override returns (string memory) {
        string memory badgeURI = badgeTypes[tokenId].uri;
        if (bytes(badgeURI).length > 0) {
            return badgeURI;
        }
        return super.uri(tokenId);
    }

    function setBadgeURI(uint256 badgeTypeId, string memory newURI) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!_badgeTypeExists(badgeTypeId)) revert InvalidBadgeType(badgeTypeId);
        if (defaultURIFrozen) revert MetadataFrozen();
        if (badgeURIFrozen[badgeTypeId]) revert BadgeTypeMetadataFrozen(badgeTypeId);
        badgeTypes[badgeTypeId].uri = newURI;
    }

    function setDefaultURI(string memory newURI) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (defaultURIFrozen) revert MetadataFrozen();
        _setURI(newURI);
    }

    function isMinted(bytes32 awardIdHash) external view returns (bool) {
        return _awards[awardIdHash].badgeTypeId != 0;
    }

    function isRevoked(bytes32 awardIdHash) external view returns (bool) {
        return _awards[awardIdHash].revoked;
    }

    function revokeAward(bytes32 awardIdHash, string calldata reason) external onlyRole(OPERATOR_ROLE) {
        AwardRecord storage award = _awards[awardIdHash];
        uint256 badgeTypeId = award.badgeTypeId;
        if (badgeTypeId == 0) revert AwardNotMinted(awardIdHash);
        if (award.revoked) revert AwardRevoked(awardIdHash);
        award.revoked = true;
        emit BadgeRevoked(awardIdHash, badgeTypeId, reason);
    }

    function adminTransfer(address from, address to, bytes32 awardIdHash, string calldata requestId)
        external
        onlyRole(OPERATOR_ROLE)
    {
        if (from == address(0) || to == address(0)) revert InvalidAddress();
        uint256 badgeTypeId = _transferAward(awardIdHash, from, to, true);

        emit AdminTransfer(msg.sender, from, to, badgeTypeId, 1, requestId);
    }

    function reinstateAward(address to, bytes32 awardIdHash, string calldata reason, string calldata requestId)
        external
        onlyRole(OPERATOR_ROLE)
    {
        if (to == address(0)) revert InvalidAddress();
        AwardRecord storage award = _awards[awardIdHash];
        uint256 badgeTypeId = award.badgeTypeId;
        if (badgeTypeId == 0) revert AwardNotMinted(awardIdHash);
        if (!award.revoked) revert AwardNotRevoked(awardIdHash);

        address from = award.owner;
        if (from != to) {
            badgeTypeId = _transferAward(awardIdHash, from, to, false);
        }

        _awards[awardIdHash].revoked = false;
        emit BadgeReinstated(awardIdHash, badgeTypeId, from, to, reason, requestId);
    }

    function freezeBadgeURI(uint256 badgeTypeId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!_badgeTypeExists(badgeTypeId)) revert InvalidBadgeType(badgeTypeId);
        badgeURIFrozen[badgeTypeId] = true;
        emit BadgeURIFrozen(badgeTypeId);
    }

    function freezeDefaultURI() external onlyRole(DEFAULT_ADMIN_ROLE) {
        defaultURIFrozen = true;
        emit DefaultURIFrozen();
    }

    function totalBadgeTypes() external view returns (uint256) {
        return _nextBadgeTypeId - 1;
    }

    function hashMintAuthorization(MintAuthorization calldata auth) external view returns (bytes32) {
        return _hashTypedDataV4(_hashMintAuthorization(auth.to, auth.badgeTypeId, auth.awardIdHash, auth.nonce, auth.deadline));
    }

    function awardIdToBadgeType(bytes32 awardIdHash) external view returns (uint256) {
        return _awards[awardIdHash].badgeTypeId;
    }

    function awardOwner(bytes32 awardIdHash) external view returns (address) {
        return _awards[awardIdHash].owner;
    }

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal override {
        if (
            from != address(0) && to != address(0) && !hasRole(OPERATOR_ROLE, _msgSender())
                && !hasRole(DEFAULT_ADMIN_ROLE, _msgSender())
        ) {
            revert NonTransferable();
        }
        super._update(from, to, ids, values);
    }

    function safeTransferFrom(address, address, uint256, uint256, bytes memory) public pure override {
        revert NonTransferable();
    }

    function safeBatchTransferFrom(address, address, uint256[] memory, uint256[] memory, bytes memory)
        public
        pure
        override
    {
        revert NonTransferable();
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC1155, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _hashMintAuthorization(address to, uint256 badgeTypeId, bytes32 awardIdHash, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(MINT_AUTHORIZATION_TYPEHASH, to, badgeTypeId, awardIdHash, nonce, deadline));
    }

    function _badgeTypeExists(uint256 badgeTypeId) internal view returns (bool) {
        return badgeTypeId != 0 && badgeTypeId < _nextBadgeTypeId;
    }

    function _transferAward(bytes32 awardIdHash, address from, address to, bool rejectRevoked)
        internal
        returns (uint256 badgeTypeId)
    {
        AwardRecord storage award = _awards[awardIdHash];
        badgeTypeId = award.badgeTypeId;
        if (badgeTypeId == 0) revert AwardNotMinted(awardIdHash);
        if (rejectRevoked && award.revoked) revert AwardRevoked(awardIdHash);
        if (award.owner != from) revert AwardOwnerMismatch();

        uint256 fromBalance = balanceOf(from, badgeTypeId);
        if (fromBalance != 1) revert InvalidBalanceForAwardOwner(from, badgeTypeId, fromBalance);
        uint256 toBalance = balanceOf(to, badgeTypeId);
        if (toBalance != 0) revert AlreadyOwnsBadgeType(to, badgeTypeId);

        _safeTransferFrom(from, to, badgeTypeId, 1, "");
        award.owner = to;
    }
}
