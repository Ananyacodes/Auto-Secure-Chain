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
    mapping(address => bool) private authorizedReporters;

    uint8 public constant MAX_SEVERITY = 10;
    address public immutable owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can manage reporters");
        _;
    }

    modifier onlyAuthorizedReporter() {
        require(authorizedReporters[msg.sender], "Reporter is not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedReporters[msg.sender] = true;
        emit ReporterAuthorizationUpdated(msg.sender, true);
    }

    function recordScan(bytes32 firmwareHash, uint8 severity, string calldata metadataURI) external onlyAuthorizedReporter {
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

    function setReporterAuthorization(address reporter, bool authorized) external onlyOwner {
        require(reporter != address(0), "Invalid reporter address");
        authorizedReporters[reporter] = authorized;
        emit ReporterAuthorizationUpdated(reporter, authorized);
    }

    function hasScan(bytes32 firmwareHash) external view returns (bool) {
        return scans[firmwareHash].exists;
    }

    function isAuthorizedReporter(address reporter) external view returns (bool) {
        return authorizedReporters[reporter];
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
