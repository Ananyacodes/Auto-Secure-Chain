import { expect } from "chai";
import { ethers } from "hardhat";

describe("AutoSecure Contract", function () {
    let autoSecure;
    const contractName = "AutoSecureChain";

    beforeEach(async function () {
        const AutoSecure = await ethers.getContractFactory("AutoSecure");
        autoSecure = await AutoSecure.deploy(contractName);
        await autoSecure.deployed();
    });

    it("should deploy the contract successfully", async function () {
        expect(autoSecure.address).to.properAddress;
    });

    it("should return the configured name", async function () {
        expect(await autoSecure.getName()).to.equal(contractName);
    });
});
