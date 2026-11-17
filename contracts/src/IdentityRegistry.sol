// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract IdentityRegistry is EIP712 {
    enum Status {
        Unregistered,
        Active,
        Revoked
    }

    struct Entry {
        address controller;
        bytes32 stateCommitment;
        uint64 sequence;
        Status status;
    }

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(bytes32 agentId,bytes32 stateCommitment,uint64 sequence,uint64 deadline)");
    bytes32 private constant UPDATE_TYPEHASH =
        keccak256("UpdateState(bytes32 agentId,bytes32 stateCommitment,uint64 sequence,uint64 deadline)");
    bytes32 private constant ROTATE_TYPEHASH =
        keccak256("RotateController(bytes32 agentId,address newController,uint64 sequence,uint64 deadline)");
    bytes32 private constant ACCEPT_TYPEHASH = keccak256(
        "AcceptController(bytes32 agentId,address oldController,address newController,uint64 sequence,uint64 deadline)"
    );
    bytes32 private constant REVOKE_TYPEHASH = keccak256("Revoke(bytes32 agentId,uint64 sequence,uint64 deadline)");

    mapping(bytes32 agentId => Entry entry) public entries;

    error AlreadyRegistered();
    error InvalidAgentId();
    error InvalidController();
    error InvalidSequence();
    error NotActive();
    error UnauthorizedController();
    error ExpiredDeadline();

    event AgentRegistered(
        bytes32 indexed agentId, address indexed controller, bytes32 stateCommitment, uint64 sequence
    );
    event StateUpdated(bytes32 indexed agentId, bytes32 stateCommitment, uint64 sequence);
    event ControllerRotated(
        bytes32 indexed agentId, address indexed oldController, address indexed newController, uint64 sequence
    );
    event AgentRevoked(bytes32 indexed agentId, uint64 sequence);

    constructor() EIP712("ASL Identity Registry", "1") {}

    function register(
        bytes32 agentId,
        bytes32 stateCommitment,
        uint64 sequence,
        uint64 deadline,
        bytes calldata signature
    ) external {
        if (entries[agentId].status != Status.Unregistered) revert AlreadyRegistered();
        if (sequence != 1) revert InvalidSequence();
        _checkDeadline(deadline);

        bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, agentId, stateCommitment, sequence, deadline));
        address controller = ECDSA.recoverCalldata(_hashTypedDataV4(structHash), signature);
        if (_deriveAgentId(controller) != agentId) revert InvalidAgentId();

        entries[agentId] = Entry(controller, stateCommitment, sequence, Status.Active);
        emit AgentRegistered(agentId, controller, stateCommitment, sequence);
    }

    function updateState(
        bytes32 agentId,
        bytes32 stateCommitment,
        uint64 sequence,
        uint64 deadline,
        bytes calldata signature
    ) external {
        Entry storage entry = _activeEntry(agentId);
        _checkDeadline(deadline);
        _checkNextSequence(entry.sequence, sequence);

        bytes32 structHash = keccak256(abi.encode(UPDATE_TYPEHASH, agentId, stateCommitment, sequence, deadline));
        _checkController(entry.controller, _hashTypedDataV4(structHash), signature);

        entry.stateCommitment = stateCommitment;
        entry.sequence = sequence;
        emit StateUpdated(agentId, stateCommitment, sequence);
    }

    function rotateController(
        bytes32 agentId,
        address newController,
        uint64 sequence,
        uint64 deadline,
        bytes calldata controllerSignature,
        bytes calldata acceptanceSignature
    ) external {
        Entry storage entry = _activeEntry(agentId);
        _checkDeadline(deadline);
        _checkNextSequence(entry.sequence, sequence);
        if (newController == address(0)) revert InvalidController();

        bytes32 rotateHash = keccak256(abi.encode(ROTATE_TYPEHASH, agentId, newController, sequence, deadline));
        _checkController(entry.controller, _hashTypedDataV4(rotateHash), controllerSignature);

        bytes32 acceptHash =
            keccak256(abi.encode(ACCEPT_TYPEHASH, agentId, entry.controller, newController, sequence, deadline));
        _checkController(newController, _hashTypedDataV4(acceptHash), acceptanceSignature);

        address oldController = entry.controller;
        entry.controller = newController;
        entry.sequence = sequence;
        emit ControllerRotated(agentId, oldController, newController, sequence);
    }

    function revoke(bytes32 agentId, uint64 sequence, uint64 deadline, bytes calldata signature) external {
        Entry storage entry = _activeEntry(agentId);
        _checkDeadline(deadline);
        _checkNextSequence(entry.sequence, sequence);

        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, agentId, sequence, deadline));
        _checkController(entry.controller, _hashTypedDataV4(structHash), signature);

        entry.sequence = sequence;
        entry.status = Status.Revoked;
        emit AgentRevoked(agentId, sequence);
    }

    function _activeEntry(bytes32 agentId) private view returns (Entry storage entry) {
        entry = entries[agentId];
        if (entry.status != Status.Active) revert NotActive();
    }

    function _checkController(address expected, bytes32 digest, bytes calldata signature) private pure {
        if (ECDSA.recoverCalldata(digest, signature) != expected) revert UnauthorizedController();
    }

    function _checkNextSequence(uint64 current, uint64 next) private pure {
        if (current == type(uint64).max || next != current + 1) revert InvalidSequence();
    }

    function _checkDeadline(uint64 deadline) private view {
        if (block.timestamp > deadline) revert ExpiredDeadline();
    }

    function _deriveAgentId(address initialController) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("ASL-Agent-v1", initialController));
    }
}
