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
        expect(ethers.utils.isAddress(autoSecure.address)).to.equal(true);
    });

    it("should store the supplied name", async function () {
        expect(await autoSecure.getName()).to.equal(contractName);
    });

    it("should accept firmware provenance records and verify signatures (simulated)", async function () {
        // This is a lightweight test to simulate on-chain recording of a firmware hash
        // and ensure the contract can store/retrieve provenance strings. Real signature
        // verification would be done off-chain; on-chain we store metadata and approvals.
        const tx = await autoSecure.storeProvenance("sha256:deadbeef", "owner1");
        await tx.wait();
        const prov = await autoSecure.getProvenance(0);
        expect(prov.hash).to.equal("sha256:deadbeef");
        expect(prov.submitter).to.equal("owner1");
        expect(prov.approved).to.be.false;
    });

    it("should allow an owner to approve a provenance record", async function () {
        const tx = await autoSecure.storeProvenance("sha256:c0ffee", "owner2");
        await tx.wait();

        const approveTx = await autoSecure.approveProvenance(0);
        await approveTx.wait();

        const prov = await autoSecure.getProvenance(0);
        expect(prov.approved).to.be.true;
    });

    it("should emit a ProvenanceStored event", async function () {
        await expect(autoSecure.storeProvenance("sha256:eventtest", "owner3"))
            .to.emit(autoSecure, "ProvenanceStored")
            .withArgs(0, "sha256:eventtest", "owner3");
    });
});