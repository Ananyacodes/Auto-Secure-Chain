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

    it("should only allow authorized reporters to submit scans", async function () {
        const [, unauthorizedReporter] = await ethers.getSigners();
        const firmwareHash = ethers.utils.id("unauthorized-firmware");

        await expect(
            autoSecure.connect(unauthorizedReporter).recordScan(firmwareHash, 3, "ipfs://unauthorized"),
        ).to.be.revertedWith("Reporter is not authorized");

        await autoSecure.setReporterAuthorization(unauthorizedReporter.address, true);
        await autoSecure.connect(unauthorizedReporter).recordScan(firmwareHash, 3, "ipfs://authorized");

        const scan = await autoSecure.getScan(firmwareHash);
        expect(scan.reporter).to.equal(unauthorizedReporter.address);
    });

    it("should reject duplicate scan submissions", async function () {
        const firmwareHash = ethers.utils.id("firmware-duplicate");
        await autoSecure.recordScan(firmwareHash, 2, "ipfs://first");

        await expect(
            autoSecure.recordScan(firmwareHash, 3, "ipfs://second"),
        ).to.be.revertedWith("Scan already recorded");
    });

    it("should reject invalid scan parameters", async function () {
        await expect(
            autoSecure.recordScan(ethers.constants.HashZero, 1, "ipfs://invalid-hash"),
        ).to.be.revertedWith("Invalid firmware hash");

        await expect(
            autoSecure.recordScan(ethers.utils.id("firmware-invalid-severity"), 11, "ipfs://invalid-severity"),
        ).to.be.revertedWith("Severity out of range");

        await expect(
            autoSecure.recordScan(ethers.utils.id("firmware-invalid-metadata"), 3, ""),
        ).to.be.revertedWith("Metadata URI is required");
    });

    it("should accept severity at the maximum boundary", async function () {
        const firmwareHash = ethers.utils.id("firmware-max-severity");

        await autoSecure.recordScan(firmwareHash, 10, "ipfs://max-severity");
        const scan = await autoSecure.getScan(firmwareHash);

        expect(scan.severity).to.equal(10);
    });

    it("should restrict reporter authorization management to owner", async function () {
        const [, reporter] = await ethers.getSigners();

        await expect(
            autoSecure.connect(reporter).setReporterAuthorization(reporter.address, true),
        ).to.be.revertedWith("Only owner can manage reporters");
    });
});
