import { expect } from "chai";
import { ethers } from "hardhat";

describe("AutoSecure Contract", function () {
    let autoSecure: any;

    beforeEach(async function () {
        const AutoSecure = await ethers.getContractFactory("AutoSecure");
        autoSecure = await AutoSecure.deploy();
        await autoSecure.deployed();
    });

    it("should deploy the contract successfully", async function () {
        expect(autoSecure.address).to.properAddress;
    });

    it("should store and return a scan record", async function () {
        const [reporter] = await ethers.getSigners();
        const firmwareHash = ethers.utils.id("firmware-v1");
        const severity = 4;
        const metadataURI = "ipfs://scan-report-v1";

        await autoSecure.recordScan(firmwareHash, severity, metadataURI);

        const hasScan = await autoSecure.hasScan(firmwareHash);
        expect(hasScan).to.equal(true);

        const scan = await autoSecure.getScan(firmwareHash);
        expect(scan.severity).to.equal(severity);
        expect(scan.metadataURI).to.equal(metadataURI);
        expect(scan.reporter).to.equal(reporter.address);
        expect(scan.scannedAt).to.be.gt(0);
    });
}); 
