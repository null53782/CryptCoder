// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

contract SoftMinterRef {
    function check(
        address to,
        uint256[] memory ids,
		bytes32 digest
    ) public pure {
        require(
            keccak256(abi.encode(to, ids)) == digest,
            "Hash not registered"
        );
    }
}