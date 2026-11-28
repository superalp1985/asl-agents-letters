use alloy_primitives::{B256, U256, b256, keccak256};
use alloy_trie::{HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
use asl_types::ids::AgentId;

use super::{
    AccountProofV1, CheckpointV1, ConsensusConfigV1, EthereumLightClient, FinalizedExecution,
    ForkV1, ForksV1, IdentityProofV1, RegistryDeploymentV1, StorageProofV1, registry_slots,
};

pub const BOOTSTRAP: &[u8] = include_bytes!("../../tests/fixtures/helios/bootstrap.json");
pub const UPDATES: &[u8] = include_bytes!("../../tests/fixtures/helios/updates.json");
pub const FINALITY: &[u8] = include_bytes!("../../tests/fixtures/helios/finality.json");
pub const BOOTSTRAP_TIME: u64 = 1_691_656_535;
pub const FINALITY_NOW: u64 = 1_692_137_207;

pub struct TestChainDatabase {
    pub path: std::path::PathBuf,
}

impl TestChainDatabase {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../work/test-chain");
        std::fs::create_dir_all(&base).unwrap();
        Self {
            path: base.join(format!(
                "chain-{}-{}-{:032x}.sqlite3",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
                rand::random::<u128>()
            )),
        }
    }

    pub fn open(&self) -> asl_store::Store {
        asl_store::open_store(&self.path).unwrap()
    }
}

impl Drop for TestChainDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.path.as_os_str().to_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(path));
        }
    }
}

pub fn consensus_config() -> ConsensusConfigV1 {
    let fork = |epoch, version| ForkV1 {
        epoch,
        version: [version, 0, 0, 0],
    };
    ConsensusConfigV1 {
        version: 1,
        chain_id: 1,
        genesis_time_secs: 1_606_824_023,
        genesis_validators_root: b256!(
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        )
        .0,
        seconds_per_slot: 12,
        forks: ForksV1 {
            genesis: fork(0, 0),
            altair: fork(74_240, 1),
            bellatrix: fork(144_896, 2),
            capella: fork(194_048, 3),
            deneb: fork(269_568, 4),
            electra: fork(364_032, 5),
            fulu: fork(411_392, 6),
            gloas: fork(u64::MAX, 7),
        },
        checkpoint: CheckpointV1 {
            beacon_root: b256!("5afc212a7924789b2bc86acad3ab3a6ffb1f6e97253ea50bee7f4f51422c9275")
                .0,
            slot: 7_069_376,
        },
        max_checkpoint_age_secs: 14 * 24 * 60 * 60,
        max_finality_age_secs: 1800,
    }
}

pub fn bootstrapped() -> EthereumLightClient {
    EthereumLightClient::bootstrap(consensus_config(), BOOTSTRAP, BOOTSTRAP_TIME).unwrap()
}

#[cfg(windows)]
pub fn fixture_execution_at(
    mut head: FinalizedExecution,
    now: u64,
    height_delta: u64,
) -> FinalizedExecution {
    head.beacon_slot = consensus_config().current_slot(now).unwrap();
    head.timestamp_secs = now;
    head.block_number += height_delta;
    head
}

pub fn process_fixture_client(
    mut finalized: FinalizedExecution,
    now_secs: u64,
) -> (ConsensusConfigV1, EthereumLightClient) {
    let mut config = consensus_config();
    // Production supervisors use wall-clock time. Shift only the test fixture's
    // timeline; historical consensus evidence cannot authenticate this trie.
    config.genesis_time_secs += now_secs - BOOTSTRAP_TIME;
    finalized.timestamp_secs = now_secs;
    let client = EthereumLightClient::bootstrap(config.clone(), BOOTSTRAP, now_secs)
        .unwrap()
        .with_test_execution(finalized);
    (config, client)
}

pub fn synced() -> EthereumLightClient {
    let mut client =
        EthereumLightClient::bootstrap(consensus_config(), BOOTSTRAP, FINALITY_NOW).unwrap();
    let updates: Vec<serde_json::Value> = serde_json::from_slice(UPDATES).unwrap();
    for update in updates {
        client
            .apply_update_json(&serde_json::to_vec(&update).unwrap(), FINALITY_NOW)
            .unwrap();
    }
    client.apply_finality_json(FINALITY, FINALITY_NOW).unwrap();
    client
}

pub fn registry_values(controller: u8, sequence: u64, status: u8) -> [[u8; 32]; 3] {
    let mut values = [[0; 32]; 3];
    values[0][12..].fill(controller);
    values[1] = [42; 32];
    values[2][23] = status;
    values[2][24..].copy_from_slice(&sequence.to_be_bytes());
    values
}

pub fn proof_fixture(
    values: [[u8; 32]; 3],
    deployment_variant: u8,
) -> (RegistryDeploymentV1, FinalizedExecution, IdentityProofV1) {
    proof_fixture_for_agent(values, deployment_variant, AgentId([7; 32]))
}

pub fn proof_fixture_for_agent(
    values: [[u8; 32]; 3],
    deployment_variant: u8,
    agent: AgentId,
) -> (RegistryDeploymentV1, FinalizedExecution, IdentityProofV1) {
    let (deployment, finalized, mut proofs) =
        proof_fixtures_for_agents(&[(agent, values)], deployment_variant);
    (deployment, finalized, proofs.pop().unwrap())
}

fn registry_targets(agent: AgentId) -> ([[u8; 32]; 3], [Nibbles; 3]) {
    let slots = registry_slots(agent);
    let targets = slots.map(|slot| Nibbles::unpack(keccak256(slot)));
    (slots, targets)
}

pub fn proof_fixtures_for_agents(
    agents: &[(AgentId, [[u8; 32]; 3])],
    deployment_variant: u8,
) -> (
    RegistryDeploymentV1,
    FinalizedExecution,
    Vec<IdentityProofV1>,
) {
    let deployment = RegistryDeploymentV1 {
        version: 1,
        chain_id: 1,
        address: [deployment_variant; 20],
        runtime_code_hash: [deployment_variant; 32],
    };
    let retainer = ProofRetainer::from_iter(
        agents
            .iter()
            .flat_map(|(agent, _)| registry_targets(*agent).1),
    );
    let mut storage = HashBuilder::default().with_proof_retainer(retainer);
    let mut entries: Vec<_> = agents
        .iter()
        .flat_map(|(agent, values)| registry_targets(*agent).1.into_iter().zip(*values))
        .filter(|(_, value)| *value != [0; 32])
        .collect();
    entries.sort_by_key(|(key, _)| *key);
    for (key, value) in entries {
        storage.add_leaf(key, &alloy_rlp::encode(U256::from_be_bytes(value)));
    }
    let storage_root = storage.root();
    let storage_nodes = storage.take_proof_nodes();
    let trie_account = TrieAccount::new(
        1,
        U256::ZERO,
        storage_root,
        B256::from(deployment.runtime_code_hash),
    );
    let account_key = Nibbles::unpack(keccak256(deployment.address));
    let mut state =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([account_key]));
    state.add_leaf(account_key, &alloy_rlp::encode(trie_account));
    let state_root = state.root();
    let account_nodes = state.take_proof_nodes();
    let finalized = FinalizedExecution {
        chain_id: 1,
        beacon_slot: 7_069_376,
        block_number: 17_883_333,
        block_hash: [6; 32],
        state_root: state_root.0,
        timestamp_secs: BOOTSTRAP_TIME,
    };
    let account = AccountProofV1 {
        nonce: 1,
        balance: [0; 32],
        storage_root: storage_root.0,
        code_hash: deployment.runtime_code_hash,
        nodes: account_nodes
            .matching_nodes_sorted(&account_key)
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect(),
    };
    let proofs = agents
        .iter()
        .map(|(agent, values)| {
            let (slots, targets) = registry_targets(*agent);
            IdentityProofV1 {
                version: 1,
                agent_id: *agent,
                chain_id: deployment.chain_id,
                registry_address: deployment.address,
                block_number: finalized.block_number,
                block_hash: finalized.block_hash,
                state_root: finalized.state_root,
                account: account.clone(),
                storage: slots
                    .into_iter()
                    .zip(targets)
                    .zip(*values)
                    .map(|((slot, target), value)| StorageProofV1 {
                        slot,
                        value,
                        nodes: storage_nodes
                            .matching_nodes_sorted(&target)
                            .into_iter()
                            .map(|(_, node)| node.to_vec())
                            .collect(),
                    })
                    .collect(),
            }
        })
        .collect();
    (deployment, finalized, proofs)
}
