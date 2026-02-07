// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BadgeNFT is ERC1155, Ownable {
    uint256 private _nextBadgeTypeId;

    mapping(string => uint256) public awardIdToBadgeType;

    mapping(uint256 => string) private _badgeURIs;

    struct BadgeType {
        string name;
        string uri;
        bool exists;
    }
    mapping(uint256 => BadgeType) public badgeTypes;

    event BadgeMinted(address indexed to, uint256 indexed badgeTypeId, string awardId);
    event BadgeTypeCreated(uint256 indexed badgeTypeId, string name, string uri);

    error AlreadyMinted(string awardId);
    error InvalidAddress();
    error InvalidBadgeType(uint256 badgeTypeId);

    constructor(string memory baseURI_, address initialOwner) ERC1155(baseURI_) Ownable(initialOwner) {
        _nextBadgeTypeId = 1;
    }

    function createBadgeType(string memory name, string memory badgeURI)
        external
        onlyOwner
        returns (uint256 badgeTypeId)
    {
        badgeTypeId = _nextBadgeTypeId++;
        _badgeURIs[badgeTypeId] = badgeURI;
        badgeTypes[badgeTypeId] = BadgeType({name: name, uri: badgeURI, exists: true});
        emit BadgeTypeCreated(badgeTypeId, name, badgeURI);
    }

    function mint(address to, uint256 badgeTypeId, string calldata awardId) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (!badgeTypes[badgeTypeId].exists) revert InvalidBadgeType(badgeTypeId);
        if (awardIdToBadgeType[awardId] != 0) revert AlreadyMinted(awardId);

        _mint(to, badgeTypeId, 1, "");

        awardIdToBadgeType[awardId] = badgeTypeId;

        emit BadgeMinted(to, badgeTypeId, awardId);
    }

    function uri(uint256 tokenId) public view override returns (string memory) {
        string memory badgeURI = _badgeURIs[tokenId];
        if (bytes(badgeURI).length > 0) {
            return badgeURI;
        }
        return super.uri(tokenId);
    }

    function setBadgeURI(uint256 badgeTypeId, string memory newURI) external onlyOwner {
        if (!badgeTypes[badgeTypeId].exists) revert InvalidBadgeType(badgeTypeId);
        _badgeURIs[badgeTypeId] = newURI;
        badgeTypes[badgeTypeId].uri = newURI;
    }

    function setDefaultURI(string memory newURI) external onlyOwner {
        _setURI(newURI);
    }

    function isMinted(string calldata awardId) external view returns (bool) {
        return awardIdToBadgeType[awardId] != 0;
    }

    function totalBadgeTypes() external view returns (uint256) {
        return _nextBadgeTypeId - 1;
    }

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal override {
        if (from != address(0) && to != address(0)) {
            revert("BadgeNFT: non-transferable");
        }
        super._update(from, to, ids, values);
    }
}
