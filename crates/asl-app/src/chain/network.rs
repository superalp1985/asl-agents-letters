use asl_types::{
    ids::Hash32,
    protocol::{
        AccountProof, IdentityProof as WireIdentityProof, IdentityProofRequest, StorageProof,
    },
};

use super::{
    AccountProofV1, ChainError, IdentityProofV1, RegistryDeploymentV1, StorageProofV1,
    config::INTERFACE_VERSION,
};

pub fn identity_proof_from_wire(
    request: &IdentityProofRequest,
    proof: &WireIdentityProof,
    deployment: RegistryDeploymentV1,
) -> Result<IdentityProofV1, ChainError> {
    deployment.validate()?;
    if proof.request_id != request.request_id
        || proof.agent_id != request.agent_id
        || proof.block_hash != request.checkpoint_hash
        || proof.storage_proofs.len() != 3
    {
        return Err(ChainError::WrongContext);
    }

    Ok(IdentityProofV1 {
        version: INTERFACE_VERSION,
        agent_id: request.agent_id,
        chain_id: deployment.chain_id,
        registry_address: deployment.address,
        block_number: proof.finalized_height,
        block_hash: proof.block_hash.0,
        state_root: proof.state_root.0,
        account: AccountProofV1 {
            nonce: proof.account.nonce,
            balance: proof.account.balance,
            storage_root: proof.account.storage_root,
            code_hash: proof.account.code_hash,
            nodes: proof.account.nodes.clone(),
        },
        storage: proof
            .storage_proofs
            .iter()
            .map(|path| StorageProofV1 {
                slot: path.slot,
                value: path.value,
                nodes: path.nodes.clone(),
            })
            .collect(),
    })
}

pub(crate) fn identity_proof_to_wire(
    request: &IdentityProofRequest,
    proof: IdentityProofV1,
    signed_directory: Vec<u8>,
) -> WireIdentityProof {
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
            nodes: proof.account.nodes,
        },
        storage_proofs: proof
            .storage
            .into_iter()
            .map(|path| StorageProof {
                slot: path.slot,
                value: path.value,
                nodes: path.nodes,
            })
            .collect(),
        signed_directory,
    }
}
