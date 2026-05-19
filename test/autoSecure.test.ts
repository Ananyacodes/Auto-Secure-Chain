import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";

describe("AutoSecure Contract", function () {
    let autoSecure: any;
    let owner: SignerWithAddress;
    let approver1: SignerWithAddress;
    let approver2: SignerWithAddress;
    let nonApprover: SignerWithAddress;
    const contractName = "AutoSecureChain";
    const requiredApprovals = 2;

    beforeEach(async function () {
        [owner, approver1, approver2, nonApprover] = await ethers.getSigners();

        const AutoSecure = await ethers.getContractFactory("AutoSecure");
        autoSecure = await AutoSecure.deploy(contractName, requiredApprovals);
        await autoSecure.deployed();
    });

    describe("Deployment", function () {
        it("should deploy the contract successfully", async function () {
            expect(autoSecure.address).to.properAddress;
        });

        it("should set the correct name", async function () {
            expect(await autoSecure.getName()).to.equal(contractName);
        });

        it("should set the owner as the first approver", async function () {
            expect(await autoSecure.owner()).to.equal(owner.address);
            expect(await autoSecure.isApprover(owner.address)).to.be.true;
            expect(await autoSecure.approverCount()).to.equal(1);
        });

        it("should set the required approvals", async function () {
            expect(await autoSecure.requiredApprovals()).to.equal(requiredApprovals);
        });
    });

    describe("Access Control", function () {
        it("should allow owner to add approvers", async function () {
            await expect(autoSecure.addApprover(approver1.address))
                .to.emit(autoSecure, "ApproverAdded")
                .withArgs(approver1.address, owner.address);

            expect(await autoSecure.isApprover(approver1.address)).to.be.true;
            expect(await autoSecure.approverCount()).to.equal(2);
        });

        it("should not allow adding zero address as approver", async function () {
            await expect(autoSecure.addApprover(ethers.constants.AddressZero))
                .to.be.revertedWith("Cannot add zero address");
        });

        it("should not allow adding existing approver", async function () {
            await autoSecure.addApprover(approver1.address);
            await expect(autoSecure.addApprover(approver1.address))
                .to.be.revertedWith("Address is already an approver");
        });

        it("should allow owner to remove approvers", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.addApprover(approver2.address);

            await expect(autoSecure.removeApprover(approver1.address))
                .to.emit(autoSecure, "ApproverRemoved")
                .withArgs(approver1.address, owner.address);

            expect(await autoSecure.isApprover(approver1.address)).to.be.false;
            expect(await autoSecure.approverCount()).to.equal(2); // owner + approver2
        });

        it("should not allow removing the owner", async function () {
            await expect(autoSecure.removeApprover(owner.address))
                .to.be.revertedWith("Cannot remove owner from approvers");
        });

        it("should not allow removing the last approver", async function () {
            await expect(autoSecure.removeApprover(owner.address))
                .to.be.revertedWith("Cannot remove last approver");
        });

        it("should allow owner to change required approvals", async function () {
            await expect(autoSecure.setRequiredApprovals(3))
                .to.emit(autoSecure, "RequiredApprovalsChanged")
                .withArgs(2, 3);

            expect(await autoSecure.requiredApprovals()).to.equal(3);
        });

        it("should not allow setting required approvals to 0", async function () {
            await expect(autoSecure.setRequiredApprovals(0))
                .to.be.revertedWith("Required approvals must be greater than 0");
        });

        it("should not allow setting required approvals higher than approver count", async function () {
            await expect(autoSecure.setRequiredApprovals(5))
                .to.be.revertedWith("Required approvals cannot exceed approver count");
        });
    });

    describe("Provenance Management", function () {
        beforeEach(async function () {
            // Add approvers for testing
            await autoSecure.addApprover(approver1.address);
            await autoSecure.addApprover(approver2.address);
        });

        it("should store provenance records", async function () {
            const hash = "sha256:deadbeef";
            const submitter = "test-submitter";

            await expect(autoSecure.storeProvenance(hash, submitter, "test metadata"))
                .to.emit(autoSecure, "ProvenanceStored")
                .withArgs(0, hash, submitter, "test metadata", await ethers.provider.getBlock('latest').then(b => b.timestamp));

            const provenance = await autoSecure.getProvenance(0);
            expect(provenance.hash).to.equal(hash);
            expect(provenance.submitter).to.equal(submitter);
            expect(provenance.approved).to.be.false;
        });

        it("should store provenance with deadline", async function () {
            const futureTime = (await ethers.provider.getBlock('latest')).timestamp + 3600; // 1 hour from now

            await autoSecure.storeProvenanceWithDeadline(
                "sha256:test",
                "submitter",
                "metadata",
                futureTime
            );

            const details = await autoSecure.getProvenanceDetails(0);
            expect(details.approvalDeadline).to.equal(futureTime);
        });

        it("should auto-approve if submitter is an approver", async function () {
            const hash = "sha256:autotest";

            // Connect as approver1 and submit
            await autoSecure.connect(approver1).storeProvenance(hash, "approver1", "auto-approve test");

            const provenance = await autoSecure.getProvenance(0);
            expect(provenance.approved).to.be.true; // Should be auto-approved
        });

        it("should require multiple approvals for non-submitter approvers", async function () {
            // Set required approvals to 2
            await autoSecure.setRequiredApprovals(2);

            // Submit as non-approver
            await autoSecure.connect(nonApprover).storeProvenance("sha256:multi", "non-approver", "multi-approve test");

            // First approval
            await expect(autoSecure.connect(approver1).approveProvenance(0))
                .to.emit(autoSecure, "ProvenanceApproved")
                .withArgs(0, approver1.address, 1, 2);

            let details = await autoSecure.getProvenanceDetails(0);
            expect(details.approved).to.be.false; // Not yet approved
            expect(details.approvalCount).to.equal(1);

            // Second approval should trigger final approval
            await expect(autoSecure.connect(approver2).approveProvenance(0))
                .to.emit(autoSecure, "ProvenanceApproved")
                .withArgs(0, approver2.address, 2, 2)
                .and.to.emit(autoSecure, "SecurityAlert")
                .withArgs("PROVENANCE_APPROVED", "Provenance record has been approved", 0, approver2.address);

            details = await autoSecure.getProvenanceDetails(0);
            expect(details.approved).to.be.true;
            expect(details.approvalCount).to.equal(2);
        });

        it("should not allow double approval by same address", async function () {
            await autoSecure.connect(nonApprover).storeProvenance("sha256:double", "test", "double approve test");

            await autoSecure.connect(approver1).approveProvenance(0);

            await expect(autoSecure.connect(approver1).approveProvenance(0))
                .to.be.revertedWith("Already approved by this address");
        });

        it("should allow rejection of provenance", async function () {
            await autoSecure.connect(nonApprover).storeProvenance("sha256:reject", "test", "reject test");

            const reason = "Security concern detected";

            await expect(autoSecure.connect(approver1).rejectProvenance(0, reason))
                .to.emit(autoSecure, "ProvenanceRejected")
                .withArgs(0, approver1.address, reason)
                .and.to.emit(autoSecure, "SecurityAlert")
                .withArgs("PROVENANCE_REJECTED", reason, 0, approver1.address);
        });

        it("should track individual approvals", async function () {
            await autoSecure.connect(nonApprover).storeProvenance("sha256:track", "test", "tracking test");

            expect(await autoSecure.hasApproved(0, approver1.address)).to.be.false;

            await autoSecure.connect(approver1).approveProvenance(0);

            expect(await autoSecure.hasApproved(0, approver1.address)).to.be.true;
            expect(await autoSecure.hasApproved(0, approver2.address)).to.be.false;
        });

        it("should reject expired approvals", async function () {
            const pastTime = (await ethers.provider.getBlock('latest')).timestamp - 3600; // 1 hour ago

            await autoSecure.storeProvenanceWithDeadline(
                "sha256:expired",
                "test",
                "expired test",
                pastTime
            );

            await expect(autoSecure.connect(approver1).approveProvenance(0))
                .to.be.revertedWith("Approval deadline has passed");
        });

        it("should only allow approvers to approve", async function () {
            await autoSecure.connect(nonApprover).storeProvenance("sha256:unauthorized", "test", "unauthorized test");

            await expect(autoSecure.connect(nonApprover).approveProvenance(0))
                .to.be.revertedWith("Only approvers can call this function");
        });

        it("should only allow approvers to reject", async function () {
            await autoSecure.connect(nonApprover).storeProvenance("sha256:reject-unauth", "test", "unauthorized reject test");

            await expect(autoSecure.connect(nonApprover).rejectProvenance(0, "test"))
                .to.be.revertedWith("Only approvers can call this function");
        });
    });

    describe("Emergency Functions", function () {
        it("should allow owner to pause contract", async function () {
            await expect(autoSecure.emergencyPause())
                .to.emit(autoSecure, "SecurityAlert")
                .withArgs("CONTRACT_PAUSED", "Contract has been paused by owner", 0, owner.address);
        });

        it("should allow owner to unpause contract", async function () {
            await expect(autoSecure.emergencyUnpause())
                .to.emit(autoSecure, "SecurityAlert")
                .withArgs("CONTRACT_UNPAUSED", "Contract has been unpaused by owner", 0, owner.address);
        });
    });

    describe("View Functions", function () {
        it("should return correct provenance count", async function () {
            expect(await autoSecure.getProvenanceCount()).to.equal(0);

            await autoSecure.storeProvenance("sha256:test1", "test", "test1");
            await autoSecure.storeProvenance("sha256:test2", "test", "test2");

            expect(await autoSecure.getProvenanceCount()).to.equal(2);
        });

        it("should return detailed provenance information", async function () {
            const hash = "sha256:detailtest";
            const submitter = "detail-submitter";
            const metadata = "detailed metadata";

            await autoSecure.storeProvenance(hash, submitter, metadata);

            const details = await autoSecure.getProvenanceDetails(0);
            expect(details.hash).to.equal(hash);
            expect(details.submitter).to.equal(submitter);
            expect(details.metadata).to.equal(metadata);
            expect(details.approved).to.be.true; // Auto-approved by owner
            expect(details.approvalCount).to.equal(1);
        });
    });

    describe("Event Emission", function () {
        it("should emit all required events", async function () {
            // Test ProvenanceStored event
            await expect(autoSecure.storeProvenance("sha256:eventtest", "event-submitter", "event metadata"))
                .to.emit(autoSecure, "ProvenanceStored");

            // Test ProvenanceApproved event
            await autoSecure.connect(nonApprover).storeProvenance("sha256:eventapprove", "test", "event approve");
            await expect(autoSecure.connect(approver1).approveProvenance(1))
                .to.emit(autoSecure, "ProvenanceApproved");

            // Test SecurityAlert event for approval
            await autoSecure.connect(nonApprover).storeProvenance("sha256:eventalert", "test", "event alert");
            await autoSecure.setRequiredApprovals(1); // Set to 1 for easy approval
            await expect(autoSecure.connect(approver1).approveProvenance(2))
                .to.emit(autoSecure, "SecurityAlert")
                .withArgs("PROVENANCE_APPROVED", "Provenance record has been approved", 2, approver1.address);
        });
    });
});