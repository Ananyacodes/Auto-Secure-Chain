// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IAutoSecure.sol";

contract AutoSecure is IAutoSecure {
    struct Scan {
        uint8 severity;
        string metadataURI;
        address reporter;
        uint256 scannedAt;
        bool exists;
    }

    mapping(bytes32 => Scan) private scans;

    uint8 public constant MAX_SEVERITY = 10;

    function recordScan(bytes32 firmwareHash, uint8 severity, string calldata metadataURI) external {
        require(firmwareHash != bytes32(0), "Invalid firmware hash");
        require(severity <= MAX_SEVERITY, "Severity out of range");
        require(bytes(metadataURI).length > 0, "Metadata URI is required");
        require(!scans[firmwareHash].exists, "Scan already recorded");

        scans[firmwareHash] = Scan({
            severity: severity,
            metadataURI: metadataURI,
            reporter: msg.sender,
            scannedAt: block.timestamp,
            exists: true
        });

        emit ScanRecorded(firmwareHash, severity, metadataURI, msg.sender, block.timestamp);
    }

    function hasScan(bytes32 firmwareHash) external view returns (bool) {
        return scans[firmwareHash].exists;
    }

    function getScan(bytes32 firmwareHash) external view returns (ScanView memory) {
        Scan storage scan = scans[firmwareHash];
        require(scan.exists, "No scan found for firmware hash");
        return ScanView({
            severity: scan.severity,
            metadataURI: scan.metadataURI,
            reporter: scan.reporter,
            scannedAt: scan.scannedAt
        });
    }
}
