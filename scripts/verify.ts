import { run } from "hardhat";

async function main() {
	const [address, ...constructorArguments] = process.argv.slice(2);

	if (!address) {
		throw new Error("Usage: ts-node scripts/verify.ts <contract-address> [constructor-args...]");
	}

	await run("verify:verify", {
		address,
		constructorArguments,
	});
}

main()
	.then(() => process.exit(0))
	.catch((error) => {
		console.error(error);
		process.exit(1);
	});