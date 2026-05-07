import { ethers } from "hardhat";

async function main() {
    const [deployer] = await ethers.getSigners();
    const AutoSecure = await ethers.getContractFactory("AutoSecure");
    const autoSecure = await AutoSecure.deploy("AutoSecureChain", [deployer.address], 1);

    await autoSecure.deployed();

    console.log("AutoSecure deployed to:", autoSecure.address);
}

// Execute the deployment script
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
