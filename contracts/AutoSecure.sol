// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AutoSecure {
    struct Finding {
        uint8 severity;
        bool exists;
        bool finalized;
        uint256 submittedAt;
        address submittedBy;
    }

    string public name;
    address public admin;
    uint256 public requiredApprovals;
    uint256 public ownerCount;

    mapping(address => bool) public isOwner;
    mapping(bytes32 => Finding) public findings;
    mapping(bytes32 => uint256) public findingApprovals;
    mapping(bytes32 => mapping(address => bool)) public hasApproved;

    event FindingSubmitted(bytes32 indexed firmwareHash, uint8 severity, address indexed submittedBy);
    event FindingApproved(bytes32 indexed firmwareHash, address indexed owner, uint256 approvals, bool finalized);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event RequiredApprovalsUpdated(uint256 requiredApprovals);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this");
        _;
    }

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Only owner can call this");
        _;
    }

    constructor(string memory _name, address[] memory _owners, uint256 _requiredApprovals) {
        require(_owners.length > 0, "At least one owner required");
        require(_requiredApprovals > 0 && _requiredApprovals <= _owners.length, "Invalid approval threshold");
        name = _name;
        admin = msg.sender;
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "Owner cannot be zero address");
            require(!isOwner[owner], "Duplicate owner");
            isOwner[owner] = true;
            ownerCount += 1;
            emit OwnerAdded(owner);
        }
        requiredApprovals = _requiredApprovals;
        emit RequiredApprovalsUpdated(_requiredApprovals);
    }

    function getName() public view returns (string memory) {
        return name;
    }

    function addOwner(address owner) external onlyAdmin {
        require(owner != address(0), "Owner cannot be zero address");
        require(!isOwner[owner], "Owner already exists");
        isOwner[owner] = true;
        ownerCount += 1;
        emit OwnerAdded(owner);
    }

    function removeOwner(address owner) external onlyAdmin {
        require(isOwner[owner], "Owner does not exist");
        require(ownerCount > 1, "Cannot remove last owner");
        isOwner[owner] = false;
        ownerCount -= 1;
        if (requiredApprovals > ownerCount) {
            requiredApprovals = ownerCount;
            emit RequiredApprovalsUpdated(requiredApprovals);
        }
        emit OwnerRemoved(owner);
    }

    function setRequiredApprovals(uint256 approvals) external onlyAdmin {
        require(approvals > 0 && approvals <= ownerCount, "Invalid approval threshold");
        requiredApprovals = approvals;
        emit RequiredApprovalsUpdated(approvals);
    }

    function submitFinding(bytes32 firmwareHash, uint8 severity) external onlyOwner {
        require(!findings[firmwareHash].exists, "Finding already exists");
        findings[firmwareHash] = Finding({
            severity: severity,
            exists: true,
            finalized: false,
            submittedAt: block.timestamp,
            submittedBy: msg.sender
        });
        emit FindingSubmitted(firmwareHash, severity, msg.sender);
    }

    function approveFinding(bytes32 firmwareHash) external onlyOwner {
        Finding storage finding = findings[firmwareHash];
        require(finding.exists, "Finding does not exist");
        require(!finding.finalized, "Finding already finalized");
        require(!hasApproved[firmwareHash][msg.sender], "Owner already approved");

        hasApproved[firmwareHash][msg.sender] = true;
        findingApprovals[firmwareHash] += 1;

        if (findingApprovals[firmwareHash] >= requiredApprovals) {
            finding.finalized = true;
        }

        emit FindingApproved(firmwareHash, msg.sender, findingApprovals[firmwareHash], finding.finalized);
    }
}
