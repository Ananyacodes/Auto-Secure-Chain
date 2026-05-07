import { expect } from "chai";
import { ethers } from "hardhat";

describe("AutoSecure Contract", function () {
    let autoSecure: any;
    let owner1: any;
    let owner2: any;
    let outsider: any;

    beforeEach(async function () {
        [owner1, owner2, outsider] = await ethers.getSigners();
        const AutoSecure = await ethers.getContractFactory("AutoSecure");
        autoSecure = await AutoSecure.deploy("AutoSecureChain", [owner1.address, owner2.address], 2);
        await autoSecure.deployed();
    });

    it("should deploy the contract successfully", async function () {
        expect(autoSecure.address).to.properAddress;
        expect(await autoSecure.ownerCount()).to.equal(2);
        expect(await autoSecure.requiredApprovals()).to.equal(2);
    });

    it("requires multi-owner approvals before finalizing a finding", async function () {
        const firmwareHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("firmware-v1"));

        await expect(autoSecure.connect(owner1).submitFinding(firmwareHash, 3))
            .to.emit(autoSecure, "FindingSubmitted")
            .withArgs(firmwareHash, 3, owner1.address);

        await expect(autoSecure.connect(owner1).approveFinding(firmwareHash))
            .to.emit(autoSecure, "FindingApproved")
            .withArgs(firmwareHash, owner1.address, 1, false);
        expect((await autoSecure.findings(firmwareHash)).finalized).to.equal(false);

        await expect(autoSecure.connect(owner2).approveFinding(firmwareHash))
            .to.emit(autoSecure, "FindingApproved")
            .withArgs(firmwareHash, owner2.address, 2, true);
        expect((await autoSecure.findings(firmwareHash)).finalized).to.equal(true);
    });

    it("rejects non-owner submissions and approvals", async function () {
        const firmwareHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("firmware-v2"));
        await expect(autoSecure.connect(outsider).submitFinding(firmwareHash, 1)).to.be.revertedWith("Only owner can call this");

        await autoSecure.connect(owner1).submitFinding(firmwareHash, 1);
        await expect(autoSecure.connect(outsider).approveFinding(firmwareHash)).to.be.revertedWith("Only owner can call this");
    });
});
