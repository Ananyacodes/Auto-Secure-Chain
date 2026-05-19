// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAutoSecure {
    struct ScanView {
        uint8 severity;
        string metadataURI;
        address reporter;
        uint256 scannedAt;
    }

    event ScanRecorded(
        bytes32 indexed firmwareHash,
        uint8 severity,
        string metadataURI,
        address indexed reporter,
        uint256 scannedAt
    );

    function recordScan(bytes32 firmwareHash, uint8 severity, string calldata metadataURI) external;

    function hasScan(bytes32 firmwareHash) external view returns (bool);

    function getScan(bytes32 firmwareHash) external view returns (ScanView memory);
}
