export const SUPPORTED_CHAIN_IDS = [1, 11155111, 31337] as const;

export function isSupportedChainId(chainId: number): boolean {
	return SUPPORTED_CHAIN_IDS.includes(chainId as (typeof SUPPORTED_CHAIN_IDS)[number]);
}

export function normalizeAddress(address: string): string {
	return address.trim().toLowerCase();
}