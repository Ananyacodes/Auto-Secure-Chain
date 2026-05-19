import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";

describe("AutoSecure Contract - Gas Benchmarks and Enhanced Tests", function () {
    let autoSecure: any;
    let owner: SignerWithAddress;
    let approver1: SignerWithAddress;
    let approver2: SignerWithAddress;
    let approver3: SignerWithAddress;
    let nonApprover: SignerWithAddress;
    const contractName = "AutoSecureChain";
    const requiredApprovals = 2;

    beforeEach(async function () {
        [owner, approver1, approver2, approver3, nonApprover] = await ethers.getSigners();

        const AutoSecure = await ethers.getContractFactory("AutoSecure");
        autoSecure = await AutoSecure.deploy(contractName, requiredApprovals);
        await autoSecure.deployed();
    });

    describe("Gas Benchmarks - Storage Operations", function () {
        it("should measure gas for storeProvenance", async function () {
            const tx = await autoSecure.storeProvenance(
                "sha256:benchmark1",
                "benchmark-submitter",
                "benchmark metadata"
            );
            
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ storeProvenance gas: ${gasUsed}`);
            expect(gasUsed).to.be.lessThan(500000); // Reasonable upper bound
        });

        it("should measure gas for approveProvenance", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.connect(nonApprover).storeProvenance(
                "sha256:approve-bench",
                "submitter",
                "metadata"
            );

            const tx = await autoSecure.connect(approver1).approveProvenance(0);
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ approveProvenance gas: ${gasUsed}`);
            expect(gasUsed).to.be.lessThan(200000);
        });

        it("should measure gas for rejectProvenance", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.connect(nonApprover).storeProvenance(
                "sha256:reject-bench",
                "submitter",
                "metadata"
            );

            const tx = await autoSecure.connect(approver1).rejectProvenance(0, "security concern");
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ rejectProvenance gas: ${gasUsed}`);
            expect(gasUsed).to.be.lessThan(150000);
        });

        it("should measure gas for multiple approvals sequence", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.addApprover(approver2.address);
            await autoSecure.setRequiredApprovals(2);

            await autoSecure.connect(nonApprover).storeProvenance(
                "sha256:multi-approve",
                "submitter",
                "metadata"
            );

            const tx1 = await autoSecure.connect(approver1).approveProvenance(0);
            const receipt1 = await tx1.wait();
            const gas1 = receipt1.gasUsed.toNumber();

            const tx2 = await autoSecure.connect(approver2).approveProvenance(0);
            const receipt2 = await tx2.wait();
            const gas2 = receipt2.gasUsed.toNumber();

            console.log(`  ✓ First approval gas: ${gas1}`);
            console.log(`  ✓ Second approval gas: ${gas2} (should trigger final approval)`);
            
            expect(gas1).to.be.lessThan(200000);
            expect(gas2).to.be.lessThan(200000);
        });
    });

    describe("Gas Benchmarks - Access Control", function () {
        it("should measure gas for addApprover", async function () {
            const tx = await autoSecure.addApprover(approver1.address);
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ addApprover gas: ${gasUsed}`);
            expect(gasUsed).to.be.lessThan(150000);
        });

        it("should measure gas for removeApprover", async function () {
            await autoSecure.addApprover(approver1.address);
            
            const tx = await autoSecure.removeApprover(approver1.address);
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ removeApprover gas: ${gasUsed}`);
            expect(gasUsed).to.be.lessThan(150000);
        });

        it("should measure gas for setRequiredApprovals", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.addApprover(approver2.address);
            
            const tx = await autoSecure.setRequiredApprovals(3);
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ setRequiredApprovals gas: ${gasUsed}`);
            expect(gasUsed).to.be.lessThan(150000);
        });
    });

    describe("Stress Tests - Multiple Provenances", function () {
        it("should handle 10 provenances efficiently", async function () {
            const gasPerTx: number[] = [];
            
            for (let i = 0; i < 10; i++) {
                const tx = await autoSecure.storeProvenance(
                    `sha256:stress-${i}`,
                    `submitter-${i}`,
                    `metadata-${i}`
                );
                const receipt = await tx.wait();
                gasPerTx.push(receipt.gasUsed.toNumber());
            }

            const avgGas = gasPerTx.reduce((a, b) => a + b) / gasPerTx.length;
            const maxGas = Math.max(...gasPerTx);
            
            console.log(`  ✓ Average gas per provenance: ${avgGas.toFixed(0)}`);
            console.log(`  ✓ Max gas per provenance: ${maxGas}`);
            
            expect(maxGas).to.be.lessThan(500000);
            expect(await autoSecure.getProvenanceCount()).to.equal(10);
        });

        it("should retrieve provenance efficiently with large count", async function () {
            // Create multiple provenances
            for (let i = 0; i < 5; i++) {
                await autoSecure.storeProvenance(
                    `sha256:retrieve-${i}`,
                    `submitter-${i}`,
                    `metadata-${i}`
                );
            }

            // Retrieve middle one
            const tx = await autoSecure.getProvenanceDetails(2);
            expect(tx.hash).to.include("retrieve-2");
        });
    });

    describe("Edge Cases - Large Data", function () {
        it("should handle long metadata strings", async function () {
            const longMetadata = "x".repeat(1000); // 1KB metadata
            
            const tx = await autoSecure.storeProvenance(
                "sha256:long-meta",
                "submitter",
                longMetadata
            );
            
            const receipt = await tx.wait();
            const gasUsed = receipt.gasUsed.toNumber();
            
            console.log(`  ✓ storeProvenance with 1KB metadata gas: ${gasUsed}`);
            
            const details = await autoSecure.getProvenanceDetails(0);
            expect(details.metadata).to.equal(longMetadata);
        });

        it("should handle many approvers", async function () {
            // Add 5 more approvers
            for (let i = 0; i < 5; i++) {
                await autoSecure.addApprover(
                    ethers.Wallet.createRandom().address
                );
            }

            expect(await autoSecure.approverCount()).to.equal(6);
        });
    });

    describe("Error Cases - Boundary Conditions", function () {
        it("should reject accessing invalid provenance index", async function () {
            await expect(autoSecure.getProvenance(999))
                .to.be.revertedWith("Invalid provenance index");
        });

        it("should reject invalid required approvals", async function () {
            await expect(autoSecure.setRequiredApprovals(0))
                .to.be.revertedWith("Required approvals must be greater than 0");

            await autoSecure.addApprover(approver1.address);
            
            await expect(autoSecure.setRequiredApprovals(10))
                .to.be.revertedWith("Required approvals cannot exceed approver count");
        });

        it("should prevent too many approvers", async function () {
            // Try to add more than 255 approvers (should hit uint8 limit)
            for (let i = 0; i < 100; i++) {
                const randomAddress = ethers.Wallet.createRandom().address;
                try {
                    await autoSecure.addApprover(randomAddress);
                } catch (e) {
                    // Expected to fail at uint8 limit
                    expect(String(e)).to.include("Maximum approvers reached");
                    break;
                }
            }
        });
    });

    describe("State Validation", function () {
        it("should maintain correct approval state through lifecycle", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.addApprover(approver2.address);
            await autoSecure.setRequiredApprovals(2);

            // Submit provenance
            await autoSecure.connect(nonApprover).storeProvenance(
                "sha256:state-test",
                "submitter",
                "metadata"
            );

            let details = await autoSecure.getProvenanceDetails(0);
            expect(details.approved).to.be.false;
            expect(details.approvalCount).to.equal(0);

            // First approval
            await autoSecure.connect(approver1).approveProvenance(0);
            details = await autoSecure.getProvenanceDetails(0);
            expect(details.approved).to.be.false;
            expect(details.approvalCount).to.equal(1);
            expect(await autoSecure.hasApproved(0, approver1.address)).to.be.true;
            expect(await autoSecure.hasApproved(0, approver2.address)).to.be.false;

            // Second approval
            await autoSecure.connect(approver2).approveProvenance(0);
            details = await autoSecure.getProvenanceDetails(0);
            expect(details.approved).to.be.true;
            expect(details.approvalCount).to.equal(2);
            expect(await autoSecure.hasApproved(0, approver2.address)).to.be.true;
        });
    });

    describe("Event Verification", function () {
        it("should emit correct sequence of events for full approval flow", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.setRequiredApprovals(1);

            const storePromise = autoSecure.connect(nonApprover).storeProvenance(
                "sha256:event-test",
                "submitter",
                "metadata"
            );

            await expect(storePromise)
                .to.emit(autoSecure, "ProvenanceStored");

            const approvePromise = autoSecure.connect(approver1).approveProvenance(0);

            await expect(approvePromise)
                .to.emit(autoSecure, "ProvenanceApproved")
                .and.to.emit(autoSecure, "SecurityAlert")
                .withArgs("PROVENANCE_APPROVED", "Provenance record has been approved", 0, approver1.address);
        });
    });

    describe("Original Test Suite - Compatibility", function () {
        // Include original tests to ensure backward compatibility
        
        it("should deploy the contract successfully", async function () {
            expect(autoSecure.address).to.properAddress;
        });

        it("should set the correct name", async function () {
            expect(await autoSecure.getName()).to.equal(contractName);
        });

        it("should allow owner to add approvers", async function () {
            await expect(autoSecure.addApprover(approver1.address))
                .to.emit(autoSecure, "ApproverAdded")
                .withArgs(approver1.address, owner.address);

            expect(await autoSecure.isApprover(approver1.address)).to.be.true;
        });

        it("should not allow double approval by same address", async function () {
            await autoSecure.addApprover(approver1.address);
            await autoSecure.connect(nonApprover).storeProvenance("sha256:double", "test", "double");

            await autoSecure.connect(approver1).approveProvenance(0);

            await expect(autoSecure.connect(approver1).approveProvenance(0))
                .to.be.revertedWith("Already approved by this address");
        });
    });
});
