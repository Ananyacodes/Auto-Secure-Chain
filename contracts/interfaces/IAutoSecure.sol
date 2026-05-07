// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAutoSecure {
	function name() external view returns (string memory);

	function getName() external view returns (string memory);

	function storeProvenance(string memory _hash, string memory _submitter) external returns (uint256);

	function getProvenance(uint256 _idx) external view returns (string memory hash, string memory submitter, uint256 timestamp, bool approved);

	function approveProvenance(uint256 _idx) external;

	event ProvenanceStored(uint256 indexed idx, string hash, string submitter);
}
}