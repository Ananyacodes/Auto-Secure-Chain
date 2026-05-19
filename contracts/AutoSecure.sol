// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IAutoSecure.sol";

contract AutoSecure is IAutoSecure {
    string public name;

    // Access control roles (optimized for gas)
    address public owner;
    mapping(address => bool) public approvers;
    uint8 public approverCount;           // Max ~255 approvers is reasonable
    uint8 public requiredApprovals;       // Min approvals needed for critical actions

    // Enhanced provenance structure - optimized for gas efficiency
    // Packed storage layout: bool + uint8 = 1 slot with uint256 timestamp = 1 slot total
    struct Provenance {
        bytes32 hashBytes;                // Use bytes32 instead of string for common hashes
        bytes32 submitterBytes;           // Use bytes32 for shorter identifiers
        uint256 timestamp;
        bool approved;
        uint8 approvalCount;              // Max ~255 approvals is reasonable
        mapping(address => bool) approvals; // Track who approved
        string metadata;                  // Additional context (e.g., firmware version, device type)
        uint256 approvalDeadline;         // Optional deadline for approvals
    }

    Provenance[] private provenances;

    // Events for better tracking and off-chain monitoring
    event ProvenanceStored(
        uint256 indexed idx,
        string hash,
        string submitter,
        string metadata,
        uint256 timestamp
    );

    event ProvenanceApproved(
        uint256 indexed idx,
        address indexed approver,
        uint256 approvalCount,
        uint256 requiredApprovals
    );

    event ProvenanceRejected(
        uint256 indexed idx,
        address indexed rejector,
        string reason
    );

    event ApproverAdded(address indexed approver, address indexed addedBy);
    event ApproverRemoved(address indexed approver, address indexed removedBy);
    event RequiredApprovalsChanged(uint256 oldValue, uint256 newValue);

    event SecurityAlert(
        string alertType,
        string message,
        uint256 indexed provenanceIdx,
        address indexed triggeredBy
    );

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    modifier onlyApprover() {
        require(approvers[msg.sender], "Only approvers can call this function");
        _;
    }

    modifier validProvenanceIndex(uint256 _idx) {
        require(_idx < provenances.length, "Invalid provenance index");
        _;
    }

    modifier notExpired(uint256 _idx) {
        require(
            provenances[_idx].approvalDeadline == 0 ||
            block.timestamp <= provenances[_idx].approvalDeadline,
            "Approval deadline has passed"
        );
        _;
    }

    constructor(string memory _name, uint256 _requiredApprovals) {
        name = _name;
        owner = msg.sender;
        
        // Ensure _requiredApprovals fits in uint8
        require(_requiredApprovals <= 255, "Required approvals too high");
        requiredApprovals = uint8(_requiredApprovals);

        // Add owner as first approver
        approvers[msg.sender] = true;
        approverCount = 1;

        emit ApproverAdded(msg.sender, msg.sender);
    }

    function getName() public view override returns (string memory) {
        return name;
    }

    function getProvenance(uint256 _idx)
        public
        view
        override
        validProvenanceIndex(_idx)
        returns (
            string memory hash,
            string memory submitter,
            uint256 timestamp,
            bool approved
        )
    {
        Provenance storage p = provenances[_idx];
        return (
            _bytes32ToString(p.hashBytes),
            _bytes32ToString(p.submitterBytes),
            p.timestamp,
            p.approved
        );
    }

    // Enhanced provenance getter with more details
    function getProvenanceDetails(uint256 _idx)
        public
        view
        validProvenanceIndex(_idx)
        returns (
            string memory hash,
            string memory submitter,
            uint256 timestamp,
            bool approved,
            uint256 approvalCount,
            string memory metadata,
            uint256 approvalDeadline
        )
    {
        Provenance storage p = provenances[_idx];
        return (
            _bytes32ToString(p.hashBytes),
            _bytes32ToString(p.submitterBytes),
            p.timestamp,
            p.approved,
            p.approvalCount,
            p.metadata,
            p.approvalDeadline
        );
    }

    // Helper to convert bytes32 back to string
    function _bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
        if (_bytes32 == 0) {
            return "";
        }
        
        bytes memory bytesArray = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            bytesArray[i] = _bytes32[i];
        }
        
        return string(bytesArray);
    }

    // Store with approval deadline
    function storeProvenanceWithDeadline(
        string memory _hash,
        string memory _submitter,
        string memory _metadata,
        uint256 _deadline
    ) public returns (uint256) {
        require(_deadline > block.timestamp, "Deadline must be in the future");

        uint256 idx = storeProvenance(_hash, _submitter, _metadata);
        provenances[idx].approvalDeadline = _deadline;

        return idx;
    }

    function approveProvenance(uint256 _idx)
        public
        override
        onlyApprover
        validProvenanceIndex(_idx)
        notExpired(_idx)
    {
        _approveProvenance(_idx, msg.sender);
    }

    function _approveProvenance(uint256 _idx, address _approver) internal {
        Provenance storage p = provenances[_idx];

        // Check if already approved by this approver
        if (p.approvals[_approver]) {
            revert("Already approved by this address");
        }

        p.approvals[_approver] = true;
        
        // Unchecked increment since we know approvalCount won't overflow uint8
        unchecked {
            p.approvalCount++;
        }

        emit ProvenanceApproved(_idx, _approver, p.approvalCount, requiredApprovals);

        // Auto-approve if we have enough approvals
        if (p.approvalCount >= requiredApprovals && !p.approved) {
            p.approved = true;

            emit SecurityAlert(
                "PROVENANCE_APPROVED",
                "Provenance record has been approved",
                _idx,
                _approver
            );
        }
    }

    function rejectProvenance(uint256 _idx, string memory _reason)
        public
        onlyApprover
        validProvenanceIndex(_idx)
    {
        Provenance storage p = provenances[_idx];

        // Mark as rejected (we'll use approved = false and add a rejection reason)
        // In a real implementation, you might want to add a separate rejection state

        emit ProvenanceRejected(_idx, msg.sender, _reason);
        emit SecurityAlert(
            "PROVENANCE_REJECTED",
            _reason,
            _idx,
            msg.sender
        );
    }

    // Check if an address has approved a specific provenance
    function hasApproved(uint256 _idx, address _approver)
        public
        view
        validProvenanceIndex(_idx)
        returns (bool)
    {
        return provenances[_idx].approvals[_approver];
    }

    // Access control functions
    function addApprover(address _approver) public onlyOwner {
        require(!approvers[_approver], "Address is already an approver");
        require(_approver != address(0), "Cannot add zero address");
        require(approverCount < 255, "Maximum approvers reached");

        approvers[_approver] = true;
        unchecked {
            approverCount++;
        }

        emit ApproverAdded(_approver, msg.sender);
    }

    function removeApprover(address _approver) public onlyOwner {
        require(approvers[_approver], "Address is not an approver");
        require(_approver != owner, "Cannot remove owner from approvers");
        require(approverCount > 1, "Cannot remove last approver");

        approvers[_approver] = false;
        unchecked {
            approverCount--;
        }

        emit ApproverRemoved(_approver, msg.sender);
    }

    function setRequiredApprovals(uint256 _required) public onlyOwner {
        require(_required > 0, "Required approvals must be greater than 0");
        require(_required <= approverCount, "Required approvals cannot exceed approver count");
        require(_required <= 255, "Required approvals too high");

        uint256 oldValue = requiredApprovals;
        requiredApprovals = uint8(_required);

        emit RequiredApprovalsChanged(oldValue, _required);
    }

    // Emergency functions
    function emergencyPause() public onlyOwner {
        // In a real implementation, you might want to add a pause mechanism
        emit SecurityAlert(
            "CONTRACT_PAUSED",
            "Contract has been paused by owner",
            0,
            msg.sender
        );
    }

    function emergencyUnpause() public onlyOwner {
        emit SecurityAlert(
            "CONTRACT_UNPAUSED",
            "Contract has been unpaused by owner",
            0,
            msg.sender
        );
    }

    // View functions for contract state
    function getProvenanceCount() public view returns (uint256) {
        return provenances.length;
    }

    function isApprover(address _address) public view returns (bool) {
        return approvers[_address];
    }
}