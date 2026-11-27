use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{B256, hex, keccak256};
use asl_types::{
    error::AslError,
    ids::{AgentId, Signature65},
};
use serde::Serialize;

use crate::{chain::RegistryDeploymentV1, identity::AgentIdentity};

const DOMAIN_NAME: &[u8] = b"ASL Identity Registry";
const DOMAIN_VERSION: &[u8] = b"1";
const DOMAIN_TYPEHASH: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const REGISTER_TYPEHASH: &[u8] =
    b"Register(bytes32 agentId,bytes32 stateCommitment,uint64 sequence,uint64 deadline)";
const REGISTER_SELECTOR: &[u8] = b"register(bytes32,bytes32,uint64,uint64,bytes)";
const UPDATE_TYPEHASH: &[u8] =
    b"UpdateState(bytes32 agentId,bytes32 stateCommitment,uint64 sequence,uint64 deadline)";
const UPDATE_SELECTOR: &[u8] = b"updateState(bytes32,bytes32,uint64,uint64,bytes)";

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistrationRequest {
    pub schema: &'static str,
    pub operation: &'static str,
    pub chain_id: u64,
    pub registry: String,
    pub agent_id: String,
    pub controller: String,
    pub sequence: u64,
    pub deadline: u64,
    pub state_commitment: String,
    pub digest: String,
    pub signature: String,
    pub calldata: String,
}

impl IdentityRegistrationRequest {
    pub fn build(
        identity: &AgentIdentity,
        deployment: RegistryDeploymentV1,
        state_commitment: [u8; 32],
        deadline: u64,
    ) -> Result<Self, AslError> {
        Self::build_with(
            "register",
            REGISTER_TYPEHASH,
            REGISTER_SELECTOR,
            identity,
            deployment,
            state_commitment,
            1,
            deadline,
        )
    }

    pub fn build_update(
        identity: &AgentIdentity,
        deployment: RegistryDeploymentV1,
        state_commitment: [u8; 32],
        sequence: u64,
        deadline: u64,
    ) -> Result<Self, AslError> {
        if sequence <= 1 {
            return Err(AslError::InvalidMessage);
        }
        Self::build_with(
            "update",
            UPDATE_TYPEHASH,
            UPDATE_SELECTOR,
            identity,
            deployment,
            state_commitment,
            sequence,
            deadline,
        )
    }

    fn build_with(
        operation: &'static str,
        typehash: &[u8],
        selector: &[u8],
        identity: &AgentIdentity,
        deployment: RegistryDeploymentV1,
        state_commitment: [u8; 32],
        sequence: u64,
        deadline: u64,
    ) -> Result<Self, AslError> {
        if deadline == 0 {
            return Err(AslError::InvalidMessage);
        }
        deployment
            .validate()
            .map_err(|_| AslError::InvalidIdentity)?;
        let domain = domain_separator(deployment);
        let struct_hash = register_struct_hash(
            typehash,
            identity.agent_id(),
            state_commitment,
            sequence,
            deadline,
        );
        let digest = eip712_digest(domain, struct_hash);
        let signature = identity.sign_prehash(digest.as_slice())?;
        let calldata = registration_calldata(
            selector,
            identity.agent_id(),
            state_commitment,
            sequence,
            deadline,
            signature,
        );
        Ok(Self {
            schema: "asl-identity-registration-v1",
            operation,
            chain_id: deployment.chain_id,
            registry: format!("0x{}", hex::encode(deployment.address)),
            agent_id: format!("0x{}", hex::encode(identity.agent_id().as_bytes())),
            controller: format!("0x{}", hex::encode(identity.controller_address())),
            sequence,
            deadline,
            state_commitment: format!("0x{}", hex::encode(state_commitment)),
            digest: format!("0x{}", hex::encode(digest.as_slice())),
            signature: format!("0x{}", hex::encode(signature.0)),
            calldata: format!("0x{}", hex::encode(calldata)),
        })
    }
}

pub fn default_state_commitment(identity: &AgentIdentity) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ASL-REGISTRATION-STATE-v1\0");
    hasher.update(identity.agent_id().as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn default_deadline() -> Result<u64, AslError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AslError::ExpiredMessage)?
        .as_secs()
        .checked_add(3600)
        .ok_or(AslError::InvalidMessage)
}

fn domain_separator(deployment: RegistryDeploymentV1) -> B256 {
    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(keccak256(DOMAIN_TYPEHASH).as_slice());
    encoded.extend_from_slice(keccak256(DOMAIN_NAME).as_slice());
    encoded.extend_from_slice(keccak256(DOMAIN_VERSION).as_slice());
    encoded.extend_from_slice(&uint256(deployment.chain_id));
    encoded.extend_from_slice(&address_word(deployment.address));
    keccak256(encoded)
}

fn register_struct_hash(
    typehash: &[u8],
    agent: AgentId,
    state_commitment: [u8; 32],
    sequence: u64,
    deadline: u64,
) -> B256 {
    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(keccak256(typehash).as_slice());
    encoded.extend_from_slice(agent.as_bytes());
    encoded.extend_from_slice(&state_commitment);
    encoded.extend_from_slice(&uint256(sequence));
    encoded.extend_from_slice(&uint256(deadline));
    keccak256(encoded)
}

fn eip712_digest(domain: B256, struct_hash: B256) -> B256 {
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(&[0x19, 0x01]);
    encoded.extend_from_slice(domain.as_slice());
    encoded.extend_from_slice(struct_hash.as_slice());
    keccak256(encoded)
}

fn registration_calldata(
    selector: &[u8],
    agent: AgentId,
    state_commitment: [u8; 32],
    sequence: u64,
    deadline: u64,
    signature: Signature65,
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 7 * 32);
    calldata.extend_from_slice(&keccak256(selector)[..4]);
    calldata.extend_from_slice(agent.as_bytes());
    calldata.extend_from_slice(&state_commitment);
    calldata.extend_from_slice(&uint256(sequence));
    calldata.extend_from_slice(&uint256(deadline));
    calldata.extend_from_slice(&uint256(5 * 32));
    calldata.extend_from_slice(&uint256(signature.0.len() as u64));
    calldata.extend_from_slice(&signature.0);
    calldata.resize(4 + 8 * 32, 0);
    calldata
}

fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn uint256(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}
