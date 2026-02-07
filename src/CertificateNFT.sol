// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";


contract CertificateNFT is ERC721, ERC721URIStorage, Ownable {
    event Minted(address indexed to, uint256 indexed tokenId, bytes32 indexed certificateId);

    mapping(bytes32 => uint256) public certificateToTokenId;

    mapping(uint256 => bytes32) public tokenIdToCertificate;

    uint256 private _nextTokenId;

    constructor(
        string memory name_,
        string memory symbol_
    ) ERC721(name_, symbol_) Ownable(msg.sender) {
        _nextTokenId = 1;
    }

    function mint(bytes32 certificateId, string calldata tokenURI_) external {
        require(certificateId != bytes32(0), "INVALID_CERTIFICATE_ID");
        require(certificateToTokenId[certificateId] == 0, "CERTIFICATE_MINTED");

        uint256 tokenId = _nextTokenId;
        _nextTokenId += 1;

        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, tokenURI_);

        certificateToTokenId[certificateId] = tokenId;
        tokenIdToCertificate[tokenId] = certificateId;

        emit Minted(msg.sender, tokenId, certificateId);
    }

    function isMinted(bytes32 certificateId) external view returns (bool) {
        return certificateToTokenId[certificateId] != 0;
    }

    function totalSupply() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}