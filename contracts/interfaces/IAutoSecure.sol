// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAutoSecure {
    // Core functions
    function name() external view returns (string memory);
    function getName() external view returns (string memory);
    function storeProvenance(string memory _hash, string memory _submitter) external returns (uint256);
    function getProvenance(uint256 _idx) external view returns (string memory hash, string memory submitter, uint256 timestamp, bool approved);
    function approveProvenance(uint256 _idx) external;

    // Enhanced functions
    function storeProvenanceWithDeadline(string memory _hash, string memory _submitter, string memory _metadata, uint256 _deadline) external returns (uint256);
    function getProvenanceDetails(uint256 _idx) external view returns (string memory hash, string memory submitter, uint256 timestamp, bool approved, uint256 approvalCount, string memory metadata, uint256 approvalDeadline);
    function rejectProvenance(uint256 _idx, string memory _reason) external;
    function hasApproved(uint256 _idx, address _approver) external view returns (bool);

    // Access control
    function addApprover(address _approver) external;
    function removeApprover(address _approver) external;
    function setRequiredApprovals(uint256 _required) external;
    function isApprover(address _address) external view returns (bool);

    // View functions
    function getProvenanceCount() external view returns (uint256);
    function owner() external view returns (address);
    function approvers(address) external view returns (bool);
    function approverCount() external view returns (uint256);
    function requiredApprovals() external view returns (uint256);

    // Emergency functions
    function emergencyPause() external;
    function emergencyUnpause() external;

    // Events
    event ProvenanceStored(uint256 indexed idx, string hash, string submitter, string metadata, uint256 timestamp);
    event ProvenanceApproved(uint256 indexed idx, address indexed approver, uint256 approvalCount, uint256 requiredApprovals);
    event ProvenanceRejected(uint256 indexed idx, address indexed rejector, string reason);
    event ApproverAdded(address indexed approver, address indexed addedBy);
    event ApproverRemoved(address indexed approver, address indexed removedBy);
    event RequiredApprovalsChanged(uint256 oldValue, uint256 newValue);
    event SecurityAlert(string alertType, string message, uint256 indexed provenanceIdx, address indexed triggeredBy);
}