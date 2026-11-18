use asl_types::{
    ids::{AgentId, Hash32, Id128},
    protocol::{
        AccountProof, IdentityProof as WireIdentityProof, IdentityProofRequest, StorageProof,
    },
};

use super::{
    ChainError, EthereumProofVerifier, IdentityProofVerifier, identity_proof_from_wire,
    test_support::{proof_fixture, registry_values},
};

fn wire_proof(request: &IdentityProofRequest, proof: &super::IdentityProofV1) -> WireIdentityProof {
    WireIdentityProof {
        request_id: request.request_id,
        agent_id: proof.agent_id,
        finalized_height: proof.block_number,
        block_hash: Hash32(proof.block_hash),
        state_root: Hash32(proof.state_root),
        account: AccountProof {
            nonce: proof.account.nonce,
            balance: proof.account.balance,
            storage_root: proof.account.storage_root,
            code_hash: proof.account.code_hash,
            nodes: proof.account.nodes.clone(),
        },
        storage_proofs: proof
            .storage
            .iter()
            .map(|path| StorageProof {
                slot: path.slot,
                value: path.value,
                nodes: path.nodes.clone(),
            })
            .collect(),
        signed_directory: vec![1, 2, 3],
    }
}

#[test]
fn wire_proof_maps_to_the_existing_mpt_verifier_without_remote_registry_context() {
    let agent = AgentId([7; 32]);
    let (deployment, finalized, expected) = proof_fixture(registry_values(4, 8, 1), 9);
    let request = IdentityProofRequest {
        request_id: Id128([1; 16]),
        agent_id: agent,
        checkpoint_hash: Hash32(finalized.block_hash()),
    };
    let wire = wire_proof(&request, &expected);

    let mapped = identity_proof_from_wire(&request, &wire, deployment).unwrap();
    assert_eq!(mapped, expected);
    EthereumProofVerifier::new(deployment)
        .unwrap()
        .verify(&finalized, agent, &mapped)
        .unwrap();
}

#[test]
fn wire_proof_rejects_mismatched_pending_request_before_mapping() {
    let (deployment, finalized, expected) = proof_fixture(registry_values(4, 8, 1), 9);
    let request = IdentityProofRequest {
        request_id: Id128([1; 16]),
        agent_id: expected.agent_id,
        checkpoint_hash: Hash32(finalized.block_hash()),
    };
    let wire = wire_proof(&request, &expected);

    let mut mismatch = wire.clone();
    mismatch.request_id = Id128([2; 16]);
    assert_eq!(
        identity_proof_from_wire(&request, &mismatch, deployment),
        Err(ChainError::WrongContext)
    );

    let mut mismatch = wire.clone();
    mismatch.block_hash = Hash32([3; 32]);
    assert_eq!(
        identity_proof_from_wire(&request, &mismatch, deployment),
        Err(ChainError::WrongContext)
    );

    let mut mismatch = request.clone();
    mismatch.agent_id = AgentId([8; 32]);
    assert_eq!(
        identity_proof_from_wire(&mismatch, &wire, deployment),
        Err(ChainError::WrongContext)
    );
}
