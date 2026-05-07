// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IAutoSecure.sol";

contract AutoSecure is IAutoSecure {
    string public name;

    constructor(string memory _name) {
        name = _name;
    }

    function getName() public view override returns (string memory) {
        return name;
    }

    struct Provenance {
        string hash;
        string submitter;
        uint256 timestamp;
        bool approved;
    }

    Provenance[] private provenances;

    function storeProvenance(string memory _hash, string memory _submitter) public override returns (uint256) {
        Provenance memory p = Provenance({hash: _hash, submitter: _submitter, timestamp: block.timestamp, approved: false});
        provenances.push(p);
        uint256 idx = provenances.length - 1;
        emit ProvenanceStored(idx, _hash, _submitter);
        return idx;
    }

    function getProvenance(uint256 _idx) public view override returns (string memory hash, string memory submitter, uint256 timestamp, bool approved) {
        require(_idx < provenances.length, "index OOB");
        Provenance storage p = provenances[_idx];
        return (p.hash, p.submitter, p.timestamp, p.approved);
    }

    function approveProvenance(uint256 _idx) public override {
        require(_idx < provenances.length, "index OOB");
        provenances[_idx].approved = true;
    }
}