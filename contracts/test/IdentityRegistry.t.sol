// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IdentityRegistry} from "../src/IdentityRegistry.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function chainId(uint256 newChainId) external;
}

contract IdentityRegistryTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant ROOT_KEY = 0xA11CE;
    uint256 private constant NEXT_ROOT_KEY = 0xB0B;
    uint64 private constant DEADLINE = 2_000_100_000;
    bytes32 private constant STATE_A = keccak256("state-a");
    bytes32 private constant STATE_B = keccak256("state-b");

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
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

    IdentityRegistry private registry;

    function setUp() public {
        vm.chainId(31_337);
        vm.warp(2_000_000_000);
        registry = new IdentityRegistry();
    }

    function test_registersAgentIdDerivedFromInitialController() public {
        address controller = vm.addr(ROOT_KEY);
        bytes32 agentId = _agentId(controller);

        registry.register(
            agentId,
            STATE_A,
            1,
            DEADLINE,
            _registerSignature(ROOT_KEY, agentId, STATE_A, 1, DEADLINE, address(registry), block.chainid)
        );

        (address storedController, bytes32 stateCommitment, uint64 sequence, IdentityRegistry.Status status) =
            registry.entries(agentId);
        require(storedController == controller, "controller");
        require(stateCommitment == STATE_A, "state commitment");
        require(sequence == 1, "sequence");
        require(status == IdentityRegistry.Status.Active, "status");
    }

    function test_rejectsRegistrationForAnotherAgentId() public {
        bytes32 agentId = bytes32(uint256(1));
        bytes memory signature =
            _registerSignature(ROOT_KEY, agentId, STATE_A, 1, DEADLINE, address(registry), block.chainid);

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_A, 1, DEADLINE, signature)));
    }

    function test_rejectsDuplicateRegistration() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        bytes memory signature =
            _registerSignature(ROOT_KEY, agentId, STATE_B, 1, DEADLINE, address(registry), block.chainid);

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_B, 1, DEADLINE, signature)));
    }

    function test_rejectsForgedRegistrationSignature() public {
        bytes32 agentId = _agentId(vm.addr(ROOT_KEY));

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_A, 1, DEADLINE, new bytes(65))));
    }

    function test_rejectsSignatureForAnotherContractDomain() public {
        bytes32 agentId = _agentId(vm.addr(ROOT_KEY));
        bytes memory signature = _registerSignature(
            ROOT_KEY, agentId, STATE_A, 1, DEADLINE, address(uint160(address(registry)) + 1), block.chainid
        );

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_A, 1, DEADLINE, signature)));
    }

    function test_rejectsSignatureForAnotherChainId() public {
        bytes32 agentId = _agentId(vm.addr(ROOT_KEY));
        bytes memory signature =
            _registerSignature(ROOT_KEY, agentId, STATE_A, 1, DEADLINE, address(registry), block.chainid + 1);

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_A, 1, DEADLINE, signature)));
    }

    function test_domainTracksChainIdChangesAfterDeployment() public {
        bytes32 agentId = _agentId(vm.addr(ROOT_KEY));
        bytes memory signature =
            _registerSignature(ROOT_KEY, agentId, STATE_A, 1, DEADLINE, address(registry), block.chainid);
        vm.chainId(block.chainid + 1);

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_A, 1, DEADLINE, signature)));
    }

    function test_rejectsRepeatedSequence() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        bytes memory signature = _updateSignature(ROOT_KEY, agentId, STATE_B, 1, DEADLINE, block.chainid);

        _expectRevert(abi.encodeCall(registry.updateState, (agentId, STATE_B, 1, DEADLINE, signature)));
    }

    function test_rejectsJumpedSequence() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        bytes memory signature = _updateSignature(ROOT_KEY, agentId, STATE_B, 3, DEADLINE, block.chainid);

        _expectRevert(abi.encodeCall(registry.updateState, (agentId, STATE_B, 3, DEADLINE, signature)));
    }

    function test_rejectsExpiredRegistration() public {
        uint64 deadline = uint64(block.timestamp - 1);
        bytes32 agentId = _agentId(vm.addr(ROOT_KEY));
        bytes memory signature =
            _registerSignature(ROOT_KEY, agentId, STATE_A, 1, deadline, address(registry), block.chainid);

        _expectRevert(abi.encodeCall(registry.register, (agentId, STATE_A, 1, deadline, signature)));
    }

    function test_rejectsControllerRotationWithoutNewControllerProof() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        address oldController = vm.addr(ROOT_KEY);
        address newController = vm.addr(NEXT_ROOT_KEY);
        bytes memory oldSignature = _rotateSignature(ROOT_KEY, agentId, newController, 2, DEADLINE, block.chainid);

        _expectRevert(
            abi.encodeCall(
                registry.rotateController, (agentId, newController, 2, DEADLINE, oldSignature, new bytes(65))
            )
        );

        (address storedController,,,) = registry.entries(agentId);
        require(storedController == oldController, "controller changed");
    }

    function test_acceptsControllerRotationAndNewControllerCanUpdateState() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        address oldController = vm.addr(ROOT_KEY);
        address newController = vm.addr(NEXT_ROOT_KEY);
        bytes memory oldSignature = _rotateSignature(ROOT_KEY, agentId, newController, 2, DEADLINE, block.chainid);
        bytes memory acceptance =
            _acceptSignature(NEXT_ROOT_KEY, agentId, oldController, newController, 2, DEADLINE, block.chainid);

        registry.rotateController(agentId, newController, 2, DEADLINE, oldSignature, acceptance);

        bytes memory oldControllerUpdate = _updateSignature(ROOT_KEY, agentId, STATE_B, 3, DEADLINE, block.chainid);
        _expectRevert(abi.encodeCall(registry.updateState, (agentId, STATE_B, 3, DEADLINE, oldControllerUpdate)));

        bytes memory update = _updateSignature(NEXT_ROOT_KEY, agentId, STATE_B, 3, DEADLINE, block.chainid);
        registry.updateState(agentId, STATE_B, 3, DEADLINE, update);

        (address storedController, bytes32 stateCommitment, uint64 sequence, IdentityRegistry.Status status) =
            registry.entries(agentId);
        require(storedController == newController, "controller");
        require(stateCommitment == STATE_B, "state commitment");
        require(sequence == 3, "sequence");
        require(status == IdentityRegistry.Status.Active, "status");
    }

    function test_revocationCannotBeReversedOrUpdated() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        bytes memory revoke = _revokeSignature(ROOT_KEY, agentId, 2, DEADLINE, block.chainid);
        registry.revoke(agentId, 2, DEADLINE, revoke);

        _expectRevert(abi.encodeCall(registry.updateState, (agentId, STATE_B, 3, DEADLINE, new bytes(65))));
        _expectRevert(
            abi.encodeCall(
                registry.rotateController, (agentId, vm.addr(NEXT_ROOT_KEY), 3, DEADLINE, new bytes(65), new bytes(65))
            )
        );
        _expectRevert(abi.encodeCall(registry.revoke, (agentId, 3, DEADLINE, new bytes(65))));

        (,,, IdentityRegistry.Status status) = registry.entries(agentId);
        require(status == IdentityRegistry.Status.Revoked, "status");
    }

    function test_storageLayoutMatchesPublishedSlots() public {
        bytes32 agentId = _register(ROOT_KEY, STATE_A);
        bytes32 entrySlot = keccak256(abi.encode(agentId, uint256(2)));
        bytes32 controllerSlot = vm.load(address(registry), entrySlot);
        bytes32 commitmentSlot = vm.load(address(registry), bytes32(uint256(entrySlot) + 1));
        bytes32 stateSlot = vm.load(address(registry), bytes32(uint256(entrySlot) + 2));

        require(address(uint160(uint256(controllerSlot))) == vm.addr(ROOT_KEY), "controller slot");
        require(commitmentSlot == STATE_A, "commitment slot");
        require(uint64(uint256(stateSlot)) == 1, "sequence slot");
        require(uint8(uint256(stateSlot) >> 64) == uint8(IdentityRegistry.Status.Active), "status slot");
    }

    function _register(uint256 privateKey, bytes32 stateCommitment) private returns (bytes32 agentId) {
        agentId = _agentId(vm.addr(privateKey));
        registry.register(
            agentId,
            stateCommitment,
            1,
            DEADLINE,
            _registerSignature(privateKey, agentId, stateCommitment, 1, DEADLINE, address(registry), block.chainid)
        );
    }

    function _agentId(address initialController) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("ASL-Agent-v1", initialController));
    }

    function _registerSignature(
        uint256 privateKey,
        bytes32 agentId,
        bytes32 stateCommitment,
        uint64 sequence,
        uint64 deadline,
        address verifyingContract,
        uint256 chainId
    ) private returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, agentId, stateCommitment, sequence, deadline));
        return _sign(privateKey, _typedDigest(structHash, verifyingContract, chainId));
    }

    function _updateSignature(
        uint256 privateKey,
        bytes32 agentId,
        bytes32 stateCommitment,
        uint64 sequence,
        uint64 deadline,
        uint256 chainId
    ) private returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(UPDATE_TYPEHASH, agentId, stateCommitment, sequence, deadline));
        return _sign(privateKey, _typedDigest(structHash, address(registry), chainId));
    }

    function _rotateSignature(
        uint256 privateKey,
        bytes32 agentId,
        address newController,
        uint64 sequence,
        uint64 deadline,
        uint256 chainId
    ) private returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(ROTATE_TYPEHASH, agentId, newController, sequence, deadline));
        return _sign(privateKey, _typedDigest(structHash, address(registry), chainId));
    }

    function _acceptSignature(
        uint256 privateKey,
        bytes32 agentId,
        address oldController,
        address newController,
        uint64 sequence,
        uint64 deadline,
        uint256 chainId
    ) private returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(ACCEPT_TYPEHASH, agentId, oldController, newController, sequence, deadline)
        );
        return _sign(privateKey, _typedDigest(structHash, address(registry), chainId));
    }

    function _revokeSignature(uint256 privateKey, bytes32 agentId, uint64 sequence, uint64 deadline, uint256 chainId)
        private
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, agentId, sequence, deadline));
        return _sign(privateKey, _typedDigest(structHash, address(registry), chainId));
    }

    function _typedDigest(bytes32 structHash, address verifyingContract, uint256 chainId)
        private
        pure
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("ASL Identity Registry"), keccak256("1"), chainId, verifyingContract)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 privateKey, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _expectRevert(bytes memory callData) private {
        (bool success,) = address(registry).call(callData);
        require(!success, "expected revert");
    }
}
