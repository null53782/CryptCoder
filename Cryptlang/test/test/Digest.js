const {
    loadFixture,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SoftMinter", function() {
    async function deployVoteFixture(){
        // create random wallets for signing
        const to = ethers.Wallet.createRandom();
        const ids = [1,2,3];
        
        // ethers.solidityPackedKeccak256 => keccak256(abi.encodePacked())
        const digest = ethers.solidityPackedKeccak256(["address", "uint256[]"], [to.address, ids]);
        
        // deploy the contract
        const SoftMinter = await ethers.getContractFactory("SoftMinter");
        const softminter = await SoftMinter.deploy();
        const SoftMinterRef = await ethers.getContractFactory("SoftMinterRef");
        const softminterref = await SoftMinterRef.deploy();
        return { softminter, softminterref, to, ids, digest };
    }
    describe("softminter", function(){
        it("Shouldn't fail if upload the right value", async function () {
            const { softminter, softminterref, to, ids, digest } = await loadFixture(
                deployVoteFixture
            );
            await expect(softminter.check(to, ids, digest)).to.not.be.reverted;
        });
    });
    describe("softminter(ref)", function(){
        it("Shouldn't fail if upload the right value", async function () {
            const { softminter, softminterref, to, ids, digest } = await loadFixture(
                deployVoteFixture
            );
            await expect(softminterref.check(to, ids, digest)).to.not.be.reverted;
        });
    });
});