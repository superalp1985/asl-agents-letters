use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_policy::snapshot_files::PinnedHome;
use asl_store::{Store, open_store, open_store_read_only};
use asl_types::error::AslError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    chain::{
        ChainError, ChainHttpClient, CheckpointV1, DurableIdentityResolver, EthereumLightClient,
    },
    network_identity::NetworkIdentityConfigurationV1,
    paths::AppPaths,
};

const APPLIED: &str = "chain.checkpoint_anchor_v1";
const PENDING: &str = "chain.checkpoint_pending_v1";
const ATTEMPT: &str = "chain.checkpoint_attempt_v1";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    chain_id: u64,
    configured: CheckpointV1,
    active: CheckpointV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    context: String,
    candidate: CheckpointV1,
}

#[derive(Serialize)]
pub struct CheckpointStatus {
    pub chain_id: u64,
    pub current: CheckpointV1,
    pub context: String,
    pub snapshot_present: bool,
    pub pending: Option<CheckpointV1>,
    pub last_attempt: Option<CheckpointV1>,
}

pub fn parse_candidate(slot: &str, beacon_root: &str) -> Result<CheckpointV1, AslError> {
    let slot = slot.parse().map_err(|_| AslError::InvalidMessage)?;
    let root = beacon_root.strip_prefix("0x").unwrap_or(beacon_root);
    let mut beacon_root = [0; 32];
    alloy_primitives::hex::decode_to_slice(root, &mut beacon_root)
        .map_err(|_| AslError::InvalidMessage)?;
    Ok(CheckpointV1 { beacon_root, slot })
}

pub fn status(paths: &AppPaths) -> Result<Option<CheckpointStatus>, AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    let Some(config) =
        NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
    else {
        return Ok(None);
    };
    let store = open_store_read_only(&paths.state().join("asl.sqlite3"))?;
    let anchor = anchor(&store, &config)?;
    Ok(Some(CheckpointStatus {
        chain_id: anchor.chain_id,
        current: anchor.active,
        context: context(&config, anchor.active)?,
        snapshot_present: matches_snapshot(&store, anchor)?,
        pending: read::<Request>(&store, PENDING)?.map(|request| request.candidate),
        last_attempt: read(&store, ATTEMPT)?,
    }))
}

pub fn stage(
    paths: &AppPaths,
    reviewed_context: &str,
    candidate: CheckpointV1,
) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    let config = NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
        .ok_or(AslError::InvalidIdentity)?;
    let store = open_store(&paths.state().join("asl.sqlite3"))?;
    let anchor = anchor(&store, &config)?;
    let context = context(&config, anchor.active)?;
    let now = now_secs()?;
    if reviewed_context != context || !matches_snapshot(&store, anchor)? {
        return Err(AslError::PolicyVersionConflict);
    }
    validate_candidate(&config, anchor.active, candidate, now)?;
    put(&store, PENDING, &Request { context, candidate }, now)
}

pub fn cancel(paths: &AppPaths) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store(&paths.state().join("asl.sqlite3"))?
        .take_setting(PENDING)?
        .ok_or(AslError::NotFound)?;
    Ok(())
}

pub(crate) fn prepare_startup(
    config: &mut NetworkIdentityConfigurationV1,
    database: &Path,
    store: &Store,
    http: &ChainHttpClient,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), AslError> {
    prepare(config, database, store, now_secs, |replacement, now| {
        runtime.block_on(async {
            let mut client = http.bootstrap(replacement, now).await?;
            if client.finalized(now) == Err(ChainError::StaleFinality) {
                http.synchronize_light_client(&mut client, now).await?;
            }
            Ok(client)
        })
    })
    .map(|_| ())
}

fn prepare(
    config: &mut NetworkIdentityConfigurationV1,
    database: &Path,
    store: &Store,
    clock: impl Fn() -> Result<u64, AslError>,
    verify: impl FnOnce(crate::chain::ConsensusConfigV1, u64) -> Result<EthereumLightClient, ChainError>,
) -> Result<bool, AslError> {
    let anchor = anchor(store, config)?;
    let expected_context = context(config, anchor.active)?;
    config.resolver.consensus.checkpoint = anchor.active;
    let Some(request) = store.take_setting(PENDING)? else {
        return Ok(true);
    };
    let request: Request =
        serde_json::from_str(&request).map_err(|_| AslError::InvalidPolicyState)?;
    let now = clock()?;
    put(store, ATTEMPT, &request.candidate, now)?;
    if request.context != expected_context
        || !matches_snapshot(store, anchor)?
        || validate_candidate(config, anchor.active, request.candidate, now).is_err()
    {
        return Ok(false);
    }
    let mut replacement = config.resolver.consensus.clone();
    replacement.checkpoint = request.candidate;
    let Ok(light_client) = verify(replacement, now) else {
        return Ok(false);
    };
    let new_anchor = Anchor {
        active: request.candidate,
        ..anchor
    };
    let value = serde_json::to_string(&new_anchor).map_err(|_| AslError::InvalidPolicyState)?;
    if DurableIdentityResolver::renew_checkpoint_with_setting(
        open_store(database)?,
        config.resolver.clone(),
        light_client,
        clock()?,
        Some((APPLIED, &value)),
    )
    .is_err()
    {
        return Ok(false);
    }
    config.resolver.consensus.checkpoint = new_anchor.active;
    Ok(true)
}

fn validate_candidate(
    config: &NetworkIdentityConfigurationV1,
    current: CheckpointV1,
    candidate: CheckpointV1,
    now: u64,
) -> Result<(), AslError> {
    let consensus = &config.resolver.consensus;
    let timestamp = consensus
        .slot_time(candidate.slot)
        .map_err(|_| AslError::InvalidIdentity)?;
    if candidate.slot <= current.slot
        || candidate.beacon_root == current.beacon_root
        || candidate.beacon_root == [0; 32]
        || timestamp > now
        || now - timestamp > consensus.max_checkpoint_age_secs
    {
        return Err(AslError::InvalidIdentity);
    }
    Ok(())
}

fn anchor(store: &Store, config: &NetworkIdentityConfigurationV1) -> Result<Anchor, AslError> {
    let consensus = &config.resolver.consensus;
    let applied = read::<Anchor>(store, APPLIED)?;
    match applied {
        Some(anchor)
            if anchor.chain_id == consensus.chain_id
                && (anchor.configured == consensus.checkpoint
                    || anchor.active == consensus.checkpoint) =>
        {
            if !matches_snapshot(store, anchor)? {
                return Err(AslError::InvalidIdentity);
            }
            Ok(Anchor {
                configured: consensus.checkpoint,
                ..anchor
            })
        }
        Some(_) => Err(AslError::InvalidIdentity),
        None => Ok(Anchor {
            chain_id: consensus.chain_id,
            configured: consensus.checkpoint,
            active: consensus.checkpoint,
        }),
    }
}

fn matches_snapshot(store: &Store, anchor: Anchor) -> Result<bool, AslError> {
    Ok(store.chain_checkpoint_hash(anchor.chain_id)? == Some(anchor.active.beacon_root))
}

fn context(
    config: &NetworkIdentityConfigurationV1,
    current: CheckpointV1,
) -> Result<String, AslError> {
    let encoded =
        serde_json::to_vec(&(config, current)).map_err(|_| AslError::InvalidPolicyState)?;
    Ok(blake3::hash(&encoded).to_hex().to_string())
}

fn read<T: DeserializeOwned>(store: &Store, key: &str) -> Result<Option<T>, AslError> {
    store
        .get_setting(key)?
        .map(|value| serde_json::from_str(&value).map_err(|_| AslError::InvalidPolicyState))
        .transpose()
}

fn put(store: &Store, key: &str, value: &impl Serialize, now: u64) -> Result<(), AslError> {
    let value = serde_json::to_string(value).map_err(|_| AslError::InvalidPolicyState)?;
    let millis = i64::try_from(now)
        .ok()
        .and_then(|now| now.checked_mul(1000))
        .ok_or(AslError::ExpiredMessage)?;
    store.set_setting(key, &value, millis)
}

fn now_secs() -> Result<u64, AslError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| AslError::ExpiredMessage)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::chain::{
        ChainEndpointV1, ChainHttpConfigV1, DurableResolverConfigV1, IdentityResolver,
        test_support::{
            BOOTSTRAP_TIME, TestChainDatabase, bootstrapped, consensus_config,
            fixture_execution_at, proof_fixture, registry_values,
        },
    };
    use asl_types::ids::AgentId;

    fn configuration() -> NetworkIdentityConfigurationV1 {
        let (deployment, _, _) = proof_fixture(registry_values(9, 7, 1), 8);
        let ep = ChainEndpointV1 {
            url: "http://127.0.0.1:1".into(),
            allow_loopback_http: true,
        };
        NetworkIdentityConfigurationV1 {
            version: 1,
            resolver: DurableResolverConfigV1 {
                consensus: consensus_config(),
                deployment,
                max_cache_age_secs: 300,
                cache_capacity: 16,
            },
            http: ChainHttpConfigV1 {
                version: 1,
                beacon_endpoints: vec![ep.clone()],
                execution_endpoints: vec![ep],
                request_timeout_ms: 250,
                max_committee_updates: 1,
                max_sync_requests: 2,
            },
        }
    }

    fn seed(database: &TestChainDatabase, config: &NetworkIdentityConfigurationV1) {
        let (deployment, head, proof) = proof_fixture(registry_values(9, 7, 1), 8);
        assert_eq!(deployment, config.resolver.deployment);
        let head = fixture_execution_at(head, BOOTSTRAP_TIME, 0);
        let mut resolver = DurableIdentityResolver::create(
            database.open(),
            config.resolver.clone(),
            bootstrapped().with_test_execution(head),
            BOOTSTRAP_TIME,
        )
        .unwrap();
        resolver
            .accept_proof(AgentId([7; 32]), &proof, BOOTSTRAP_TIME)
            .unwrap();
    }

    fn candidate(now: u64) -> CheckpointV1 {
        let (_, head, _) = proof_fixture(registry_values(9, 7, 1), 8);
        CheckpointV1 {
            beacon_root: [0x91; 32],
            slot: fixture_execution_at(head, now, 0).beacon_slot(),
        }
    }

    fn queue(
        store: &Store,
        config: &NetworkIdentityConfigurationV1,
        candidate: CheckpointV1,
        now: u64,
    ) {
        put(
            store,
            PENDING,
            &Request {
                context: context(config, config.resolver.consensus.checkpoint).unwrap(),
                candidate,
            },
            now,
        )
        .unwrap();
    }

    #[test]
    fn checkpoint_approval_survives_restart_without_rewriting_configuration() {
        let db = TestChainDatabase::new();
        let original = configuration();
        seed(&db, &original);
        let store = db.open();
        let before = store.load_chain_bundle(1).unwrap().unwrap();
        let now = BOOTSTRAP_TIME + original.resolver.consensus.max_checkpoint_age_secs + 24;
        let candidate = candidate(now);
        queue(&store, &original, candidate, now);
        let mut updated = original.clone();
        assert!(
            prepare(
                &mut updated,
                &db.path,
                &store,
                || Ok(now),
                |config, _| {
                    assert_eq!(config.checkpoint, candidate);
                    let (_, head, _) = proof_fixture(registry_values(9, 7, 2), 8);
                    let head = fixture_execution_at(head, now, 1);
                    Ok(bootstrapped()
                        .with_test_checkpoint(candidate)
                        .with_test_execution(head))
                }
            )
            .unwrap()
        );
        assert_eq!(updated.resolver.consensus.checkpoint, candidate);
        let after = store.load_chain_bundle(1).unwrap().unwrap();
        assert_eq!(after.observations, before.observations);
        assert!(after.proofs.is_empty());
        assert_eq!(after.state.checkpoint_hash, candidate.beacon_root);
        assert_eq!(
            read::<CheckpointV1>(&store, ATTEMPT).unwrap(),
            Some(candidate)
        );
        let mut restart = original;
        assert!(
            prepare(
                &mut restart,
                &db.path,
                &store,
                || Ok(now),
                |_, _| panic!("approval must not replay")
            )
            .unwrap()
        );
        let mut restored =
            DurableIdentityResolver::restore(db.open(), restart.resolver, now).unwrap();
        assert!(matches!(
            restored.resolve(AgentId([7; 32]), now),
            crate::chain::IdentityResolution::Limited(crate::chain::LimitedReason::Unknown)
        ));
    }

    #[test]
    fn failed_or_stale_checkpoint_approval_is_consumed_without_changing_chain_state() {
        let db = TestChainDatabase::new();
        let original = configuration();
        seed(&db, &original);
        let store = db.open();
        let before = store.load_chain_bundle(1).unwrap().unwrap();
        let now = BOOTSTRAP_TIME + 36;
        let candidate = candidate(now);
        queue(&store, &original, candidate, now);
        let mut changed = original.clone();
        changed.http.request_timeout_ms += 1;
        assert!(
            !prepare(
                &mut changed,
                &db.path,
                &store,
                || Ok(now),
                |_, _| panic!("changed verification context must not contact the source")
            )
            .unwrap()
        );
        assert!(store.get_setting(PENDING).unwrap().is_none());
        queue(&store, &original, candidate, now);
        let mut retry = original.clone();
        assert!(
            !prepare(
                &mut retry,
                &db.path,
                &store,
                || Ok(now),
                |_, _| Err(ChainError::InvalidCheckpoint)
            )
            .unwrap()
        );
        assert!(store.get_setting(PENDING).unwrap().is_none());
        assert!(store.get_setting(APPLIED).unwrap().is_none());
        assert_eq!(retry, original);
        assert_eq!(store.load_chain_bundle(1).unwrap().unwrap(), before);
    }
}
