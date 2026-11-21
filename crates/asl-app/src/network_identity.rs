use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_store::open_store;
use asl_types::{
    error::AslError,
    ids::PeerId,
    record::{MAX_RECORD_BYTES, MAX_RECORD_LIFETIME_MS, RecordPayload, decode_record},
};
use serde::{Deserialize, Serialize};

use crate::{
    chain::{
        ChainHttpClient, ChainHttpConfigV1, DurableIdentityResolver, DurableResolverConfigV1,
        IdentityResolution, IdentityResolver, RegistryStatus,
    },
    chain_refresh::ChainRefreshWorker,
    identity::AgentIdentity,
    paths::AppPaths,
    profile::{CoreAdmission, sign_record, verify_record},
};

const MAX_NETWORK_IDENTITY_CONFIGURATION_BYTES: u64 = 65_536;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentityConfigurationV1 {
    pub version: u16,
    pub resolver: DurableResolverConfigV1,
    pub http: ChainHttpConfigV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAdmissionStatus {
    TrustConfigurationMissing,
    DeviceDirectoryMissing,
    DeviceDirectoryUnavailable,
    ChainUnavailable,
    RegistryAnchorMissing,
    Active,
}

pub(crate) struct NetworkAdmissionSetup {
    pub status: NetworkAdmissionStatus,
    pub admission: Option<CoreAdmission>,
    pub refresh_worker: Option<ChainRefreshWorker>,
}

impl NetworkIdentityConfigurationV1 {
    pub fn load(path: &Path) -> Result<Option<Self>, AslError> {
        let Some(bytes) = read_optional_file(path, MAX_NETWORK_IDENTITY_CONFIGURATION_BYTES)?
        else {
            return Ok(None);
        };
        let configuration: Self =
            serde_json::from_slice(&bytes).map_err(|_| AslError::InvalidIdentity)?;
        if configuration.version != 1
            || DurableIdentityResolver::validate_config(&configuration.resolver).is_err()
            || ChainHttpClient::new(configuration.http.clone()).is_err()
        {
            return Err(AslError::InvalidIdentity);
        }
        Ok(Some(configuration))
    }
}

pub(crate) fn load_network_admission(
    paths: &AppPaths,
    identity: &AgentIdentity,
    local_peer_id: PeerId,
) -> Result<NetworkAdmissionSetup, AslError> {
    let Some(configuration) =
        NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
    else {
        return Ok(setup(NetworkAdmissionStatus::TrustConfigurationMissing));
    };
    let Some(signed_directory) = read_signed_device_directory(&paths.signed_device_directory())?
    else {
        return Ok(setup(NetworkAdmissionStatus::DeviceDirectoryMissing));
    };
    let http =
        ChainHttpClient::new(configuration.http.clone()).map_err(|_| AslError::InvalidIdentity)?;
    let database_path = paths.state().join("asl.sqlite3");
    let store = open_store(&database_path)?;
    let has_saved_state = store
        .load_chain_bundle(configuration.resolver.consensus.chain_id)?
        .is_some();
    let now_secs = unix_time_secs()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;

    let mut resolver = if has_saved_state {
        DurableIdentityResolver::restore(store, configuration.resolver.clone(), now_secs)
            .map_err(|_| AslError::InvalidIdentity)?
    } else {
        let light_client = match runtime
            .block_on(http.bootstrap(configuration.resolver.consensus.clone(), now_secs))
        {
            Ok(client) => client,
            Err(_) => return Ok(setup(NetworkAdmissionStatus::ChainUnavailable)),
        };
        DurableIdentityResolver::create(
            store,
            configuration.resolver.clone(),
            light_client,
            now_secs,
        )
        .map_err(|_| AslError::InvalidIdentity)?
    };

    if !is_active_identity(&mut resolver, identity, unix_time_secs()?)
        && (runtime
            .block_on(http.synchronize(&mut resolver, unix_time_secs()?))
            .is_err()
            || runtime
                .block_on(http.fetch_identity(
                    &mut resolver,
                    identity.agent_id(),
                    unix_time_secs()?,
                ))
                .is_err())
    {
        return Ok(setup(NetworkAdmissionStatus::ChainUnavailable));
    }
    if !is_active_identity(&mut resolver, identity, unix_time_secs()?) {
        return Ok(setup(NetworkAdmissionStatus::RegistryAnchorMissing));
    }

    let refresh_worker = ChainRefreshWorker::start(
        configuration.http,
        resolver.light_client().clone(),
        identity.agent_id(),
        configuration.resolver.deployment,
        configuration.resolver.max_cache_age_secs,
    )?;
    let now_ms = unix_time_ms()?;
    let signed_directory = renew_directory_envelope_if_due(
        identity,
        signed_directory,
        &database_path,
        &mut resolver,
        now_ms,
    )?;
    let admission = CoreAdmission::for_local_identity(
        identity,
        local_peer_id,
        signed_directory,
        resolver,
        now_ms,
    )?;
    Ok(NetworkAdmissionSetup {
        status: NetworkAdmissionStatus::Active,
        admission: Some(admission),
        refresh_worker: Some(refresh_worker),
    })
}

fn renew_directory_envelope_if_due(
    identity: &AgentIdentity,
    signed_directory: Vec<u8>,
    database_path: &Path,
    resolver: &mut DurableIdentityResolver,
    now_ms: u64,
) -> Result<Vec<u8>, AslError> {
    const RENEWAL_MS: u64 = 5 * 60 * 1_000;

    let record = decode_record(&signed_directory)?;
    let RecordPayload::DeviceDirectory(directory) = record.record.payload else {
        return Err(AslError::InvalidDeviceCertificate);
    };
    if directory.agent_id != identity.agent_id() {
        return Err(AslError::InvalidIdentity);
    }
    let renewal_at = record.record.issued_at_ms.saturating_add(RENEWAL_MS);
    if now_ms < record.record.expires_at_ms && now_ms < renewal_at {
        return Ok(signed_directory);
    }

    let minimum = record
        .record
        .sequence
        .checked_add(1)
        .ok_or(AslError::PolicyVersionConflict)?;
    let mut store = open_store(database_path)?;
    let sequence = store.reserve_device_directory_sequence(identity.agent_id(), minimum)?;
    let renewed = sign_record(
        identity,
        RecordPayload::DeviceDirectory(directory),
        sequence,
        now_ms,
        MAX_RECORD_LIFETIME_MS,
    )?;
    verify_record(&renewed, identity.agent_id(), now_ms, resolver)?;
    Ok(renewed)
}

pub(crate) fn read_signed_device_directory(path: &Path) -> Result<Option<Vec<u8>>, AslError> {
    read_optional_file(path, MAX_RECORD_BYTES as u64)
}

fn is_active_identity(
    resolver: &mut DurableIdentityResolver,
    identity: &AgentIdentity,
    now_secs: u64,
) -> bool {
    matches!(
        resolver.resolve(identity.agent_id(), now_secs),
        IdentityResolution::Verified(verified)
            if verified.state().status == RegistryStatus::Active
                && verified.state().controller == identity.controller_address()
    )
}

fn read_optional_file(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, AslError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(AslError::InvalidIdentity);
    }
    let file = File::open(path)?;
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(AslError::InvalidIdentity);
    }
    Ok(Some(bytes))
}

fn unix_time_secs() -> Result<u64, AslError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AslError::ExpiredMessage)
}

fn unix_time_ms() -> Result<u64, AslError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(AslError::ExpiredMessage)
}

fn setup(status: NetworkAdmissionStatus) -> NetworkAdmissionSetup {
    NetworkAdmissionSetup {
        status,
        admission: None,
        refresh_worker: None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::chain::{
        ChainEndpointV1, CheckpointV1, ConsensusConfigV1, DurableIdentityResolver,
        DurableResolverConfigV1, ForkV1, ForksV1, RegistryDeploymentV1,
        test_support::{
            BOOTSTRAP_TIME, TestChainDatabase, bootstrapped, consensus_config,
            proof_fixture_for_agent,
        },
    };
    use asl_types::record::{DeviceDirectory, RecordPayload, device_directory_commitment};

    use super::*;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let base = std::env::temp_dir().join("asl-test-network-identity");
            let root = base.join(format!(
                "config-{}-{}",
                std::process::id(),
                NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let Some(name) = self.0.file_name().and_then(|name| name.to_str()) else {
                return;
            };
            let base = self
                .0
                .parent()
                .and_then(|parent| parent.canonicalize().ok());
            let root = self.0.canonicalize().ok();
            if name.starts_with("config-")
                && base
                    .as_ref()
                    .zip(root.as_ref())
                    .is_some_and(|(base, root)| {
                        root.starts_with(base) && root.parent() == Some(base.as_path())
                    })
            {
                let _ = fs::remove_dir_all(root.unwrap());
            }
        }
    }

    fn configuration() -> NetworkIdentityConfigurationV1 {
        let fork = |epoch, version| ForkV1 {
            epoch,
            version: [version, 0, 0, 0],
        };
        NetworkIdentityConfigurationV1 {
            version: 1,
            resolver: DurableResolverConfigV1 {
                consensus: ConsensusConfigV1 {
                    version: 1,
                    chain_id: 1,
                    genesis_time_secs: 1_606_824_023,
                    genesis_validators_root: [1; 32],
                    seconds_per_slot: 12,
                    forks: ForksV1 {
                        genesis: fork(0, 0),
                        altair: fork(1, 1),
                        bellatrix: fork(2, 2),
                        capella: fork(3, 3),
                        deneb: fork(4, 4),
                        electra: fork(5, 5),
                        fulu: fork(6, 6),
                        gloas: fork(u64::MAX, 7),
                    },
                    checkpoint: CheckpointV1 {
                        beacon_root: [2; 32],
                        slot: 8,
                    },
                    max_checkpoint_age_secs: 14 * 24 * 60 * 60,
                    max_finality_age_secs: 1800,
                },
                deployment: RegistryDeploymentV1 {
                    version: 1,
                    chain_id: 1,
                    address: [3; 20],
                    runtime_code_hash: [4; 32],
                },
                max_cache_age_secs: 120,
                cache_capacity: 8,
            },
            http: ChainHttpConfigV1 {
                version: 1,
                beacon_endpoints: vec![ChainEndpointV1 {
                    url: "https://beacon.invalid".into(),
                    allow_loopback_http: false,
                }],
                execution_endpoints: vec![ChainEndpointV1 {
                    url: "https://execution.invalid".into(),
                    allow_loopback_http: false,
                }],
                request_timeout_ms: 5000,
                max_committee_updates: 8,
                max_sync_requests: 24,
            },
        }
    }

    #[test]
    fn network_identity_configuration_round_trips_and_rejects_unknown_fields() {
        let directory = TestDirectory::new();
        let path = directory.0.join("network.json");
        fs::write(&path, serde_json::to_vec(&configuration()).unwrap()).unwrap();
        assert_eq!(
            NetworkIdentityConfigurationV1::load(&path).unwrap(),
            Some(configuration())
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(NetworkIdentityConfigurationV1::load(&path).is_err());
    }

    #[test]
    fn network_identity_configuration_rejects_chain_mismatch_and_invalid_endpoints() {
        let directory = TestDirectory::new();
        let path = directory.0.join("network.json");
        let mut invalid = configuration();
        invalid.resolver.deployment.chain_id = 2;
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(NetworkIdentityConfigurationV1::load(&path).is_err());

        let mut invalid = configuration();
        invalid.http.execution_endpoints[0].url = "http://example.invalid".into();
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(NetworkIdentityConfigurationV1::load(&path).is_err());
    }

    #[test]
    fn missing_configuration_and_directory_are_distinct_pending_states() {
        let directory = TestDirectory::new();
        let paths = AppPaths::open(&directory.0.join("home")).unwrap();
        let identity = AgentIdentity::generate().unwrap();
        let peer = crate::identity::DeviceIdentity::generate()
            .unwrap()
            .peer_id();
        assert_eq!(
            load_network_admission(&paths, &identity, peer.clone())
                .unwrap()
                .status,
            NetworkAdmissionStatus::TrustConfigurationMissing
        );
        fs::write(
            paths.network_identity_configuration(),
            serde_json::to_vec(&configuration()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_network_admission(&paths, &identity, peer)
                .unwrap()
                .status,
            NetworkAdmissionStatus::DeviceDirectoryMissing
        );
    }

    #[test]
    fn oversized_local_network_configuration_is_rejected() {
        let directory = TestDirectory::new();
        let path = directory.0.join("network.json");
        fs::write(
            &path,
            vec![b' '; (MAX_NETWORK_IDENTITY_CONFIGURATION_BYTES + 1) as usize],
        )
        .unwrap();
        assert!(NetworkIdentityConfigurationV1::load(&path).is_err());
    }

    #[test]
    fn startup_renews_an_expired_directory_envelope_and_reserves_its_sequence() {
        let root = AgentIdentity::generate().unwrap();
        let peer = crate::identity::DeviceIdentity::generate()
            .unwrap()
            .peer_id();
        let now_ms = BOOTSTRAP_TIME * 1_000 + 123;
        let certificate = root
            .issue_device_certificate(peer, 1, now_ms - 1_000, now_ms + 86_400_000)
            .unwrap();
        let payload = RecordPayload::DeviceDirectory(DeviceDirectory {
            agent_id: root.agent_id(),
            registry_sequence: 7,
            devices: vec![certificate],
            revoked_serials: Vec::new(),
        });
        let RecordPayload::DeviceDirectory(directory) = &payload else {
            unreachable!()
        };
        let commitment = device_directory_commitment(directory).unwrap();
        let mut values = [[0; 32]; 3];
        values[0][12..].copy_from_slice(&root.controller_address());
        values[1] = commitment.0;
        values[2][23] = 1;
        values[2][24..].copy_from_slice(&directory.registry_sequence.to_be_bytes());
        let (deployment, finalized, proof) = proof_fixture_for_agent(values, 8, root.agent_id());
        let database = TestChainDatabase::new();
        let mut resolver = DurableIdentityResolver::create(
            database.open(),
            DurableResolverConfigV1 {
                consensus: consensus_config(),
                deployment,
                max_cache_age_secs: 900,
                cache_capacity: 8,
            },
            bootstrapped().with_test_execution(finalized),
            BOOTSTRAP_TIME,
        )
        .unwrap();
        resolver
            .accept_proof(root.agent_id(), &proof, BOOTSTRAP_TIME)
            .unwrap();
        let source = sign_record(&root, payload, 1, now_ms, 10).unwrap();

        let renewed = renew_directory_envelope_if_due(
            &root,
            source,
            &database.path,
            &mut resolver,
            now_ms + 10,
        )
        .unwrap();
        let record = decode_record(&renewed).unwrap();
        assert_eq!(record.record.sequence, 2);
        assert_eq!(record.record.issued_at_ms, now_ms + 10);
        assert_eq!(
            record.record.expires_at_ms,
            now_ms + 10 + MAX_RECORD_LIFETIME_MS
        );
        assert_eq!(
            database
                .open()
                .reserve_device_directory_sequence(root.agent_id(), 0)
                .unwrap(),
            3
        );
    }
}
