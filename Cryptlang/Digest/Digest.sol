// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.20;
contract SoftMinter {
	function check (address _to,uint256[] memory _ids,bytes32 digest) public pure
	{
		require(keccak256(abi.encodePacked(_to,_ids)) == digest, "Invalid Digest!");
	}
}
