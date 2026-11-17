use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_trie::{Nibbles, TrieAccount, proof::verify_proof};
use asl_types::ids::AgentId;

use super::{
    ChainError, FinalizedExecution, IdentityProofV1, RegistryDeploymentV1, RegistryStateV1,
    RegistryStatus, VerifiedIdentity, config::INTERFACE_VERSION,
};

const MAX_PATH_NODES: usize = 32;
const MAX_NODE_BYTES: usize = 2 * 1024;
const MAX_STORAGE_PATHS: usize = 8;
const MAX_PROOF_BYTES: usize = 256 * 1024;

pub trait IdentityProofVerifier {
    fn interface_version(&self) -> u16;

    fn verify(
        &self,
        finalized: &FinalizedExecution,
        expected_agent: AgentId,
        proof: &IdentityProofV1,
    ) -> Result<VerifiedIdentity, ChainError>;
}

#[derive(Clone)]
pub struct EthereumProofVerifier {
    deployment: RegistryDeploymentV1,
}

impl EthereumProofVerifier {
    pub fn new(deployment: RegistryDeploymentV1) -> Result<Self, ChainError> {
        deployment.validate()?;
        Ok(Self { deployment })
    }

    pub fn deployment(&self) -> RegistryDeploymentV1 {
        self.deployment
    }
}

impl IdentityProofVerifier for EthereumProofVerifier {
    fn interface_version(&self) -> u16 {
        INTERFACE_VERSION
    }

    fn verify(
        &self,
        finalized: &FinalizedExecution,
        expected_agent: AgentId,
        proof: &IdentityProofV1,
    ) -> Result<VerifiedIdentity, ChainError> {
        check_limits(proof)?;
        if proof.version != INTERFACE_VERSION
            || proof.agent_id != expected_agent
            || proof.chain_id != self.deployment.chain_id
            || proof.chain_id != finalized.chain_id
            || proof.registry_address != self.deployment.address
            || proof.block_number != finalized.block_number
            || proof.block_hash != finalized.block_hash
            || proof.state_root != finalized.state_root
            || proof.storage.len() != 3
        {
            return Err(ChainError::WrongContext);
        }

        let account = TrieAccount::new(
            proof.account.nonce,
            U256::from_be_bytes(proof.account.balance),
            B256::from(proof.account.storage_root),
            B256::from(proof.account.code_hash),
        );
        verify_path(
            finalized.state_root,
            keccak256(self.deployment.address),
            Some(alloy_rlp::encode(account)),
            &proof.account.nodes,
        )?;
        if proof.account.code_hash != self.deployment.runtime_code_hash {
            return Err(ChainError::WrongCodeHash);
        }

        let mut values = [[0; 32]; 3];
        for (index, slot) in registry_slots(expected_agent).iter().enumerate() {
            let mut matching = proof.storage.iter().filter(|path| path.slot == *slot);
            let path = matching.next().ok_or(ChainError::WrongContext)?;
            if matching.next().is_some() {
                return Err(ChainError::WrongContext);
            }
            let value = U256::from_be_bytes(path.value);
            let expected = (value != U256::ZERO).then(|| alloy_rlp::encode(value));
            verify_path(
                proof.account.storage_root,
                keccak256(slot),
                expected,
                &path.nodes,
            )?;
            values[index] = path.value;
        }

        Ok(VerifiedIdentity {
            agent_id: expected_agent,
            deployment: self.deployment,
            finalized: finalized.clone(),
            state: decode_registry_state(values)?,
        })
    }
}

pub fn registry_slots(agent: AgentId) -> [[u8; 32]; 3] {
    let mut preimage = [0; 64];
    preimage[..32].copy_from_slice(agent.as_bytes());
    preimage[63] = 2;
    let base = U256::from_be_bytes(keccak256(preimage).0);
    [
        base.to_be_bytes(),
        base.wrapping_add(U256::from(1)).to_be_bytes(),
        base.wrapping_add(U256::from(2)).to_be_bytes(),
    ]
}

fn check_limits(proof: &IdentityProofV1) -> Result<(), ChainError> {
    if proof.storage.len() > MAX_STORAGE_PATHS {
        return Err(ChainError::ProofTooLarge);
    }
    // Reserve space for the fixed fields, slot values, and CBOR length prefixes.
    // The eventual stream codec must also cap the original encoded frame.
    let mut bytes = 256 + proof.storage.len() * 80;
    for path in
        std::iter::once(&proof.account.nodes).chain(proof.storage.iter().map(|path| &path.nodes))
    {
        if path.len() > MAX_PATH_NODES {
            return Err(ChainError::ProofTooLarge);
        }
        for node in path {
            if node.is_empty() || node.len() > MAX_NODE_BYTES {
                return Err(ChainError::ProofTooLarge);
            }
            bytes += node.len() + 3;
            if bytes > MAX_PROOF_BYTES {
                return Err(ChainError::ProofTooLarge);
            }
        }
    }
    Ok(())
}

fn verify_path(
    root: [u8; 32],
    hashed_key: B256,
    expected_value: Option<Vec<u8>>,
    nodes: &[Vec<u8>],
) -> Result<(), ChainError> {
    let nodes: Vec<Bytes> = nodes
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect();
    verify_proof(
        B256::from(root),
        Nibbles::unpack(hashed_key),
        expected_value,
        &nodes,
    )
    .map_err(|_| ChainError::InvalidProof)
}

fn decode_registry_state(values: [[u8; 32]; 3]) -> Result<RegistryStateV1, ChainError> {
    if values[0][..12] != [0; 12] || values[2][..23] != [0; 23] {
        return Err(ChainError::InvalidRegistryState);
    }
    let mut controller = [0; 20];
    controller.copy_from_slice(&values[0][12..]);
    let mut sequence_bytes = [0; 8];
    sequence_bytes.copy_from_slice(&values[2][24..]);
    let sequence = u64::from_be_bytes(sequence_bytes);
    let status = match values[2][23] {
        0 if values == [[0; 32]; 3] => RegistryStatus::Unregistered,
        1 if sequence > 0 && controller != [0; 20] => RegistryStatus::Active,
        2 if sequence > 0 && controller != [0; 20] => RegistryStatus::Revoked,
        _ => return Err(ChainError::InvalidRegistryState),
    };
    Ok(RegistryStateV1 {
        controller,
        state_commitment: values[1],
        sequence,
        status,
    })
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
