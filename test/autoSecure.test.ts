import { expect } from "chai";
import { ethers } from "hardhat";

describe("AutoSecure Contract", function () {
    let autoSecure;

    beforeEach(async function () {
        const AutoSecure = await ethers.getContractFactory("AutoSecure");
        autoSecure = await AutoSecure.deploy();
        await autoSecure.deployed();
    });

    it("should deploy the contract successfully", async function () {
        expect(autoSecure.address).to.properAddress;
    });

    // Add more tests as needed
});