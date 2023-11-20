// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.20;
import { Distributor } from "./Distributor.sol" ;
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol" ;
contract MerkleDistributor is Distributor {
	bytes32 public merkleRoot;
	constructor(bytes32 merkleRoot_) {
		merkleRoot = merkleRoot_;
	}
	function claim (uint256 _index,address _account,uint256 _amount,bytes32[] calldata merkleProof) public virtual
	{
		require(!isClaimed(_index),"Already Claimed!");
		bytes32 node = keccak256(abi.encodePacked(_index,_account,_amount));
		require(MerkleProof.verify(merkleProof, merkleRoot, node), "Invalid MerkleProof!");
		_setClaimed(_index);
		transfer(_account,_amount);
	}
}
