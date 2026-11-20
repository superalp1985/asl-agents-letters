use asl_net::dht::{
    BoundedRecordStore, MAX_DHT_RECORDS, MAX_DHT_VALUE_BYTES, concept_key, content_key, handle_key,
    identity_record_key,
};
use asl_types::{
    ids::{AgentId, Hash32, Signature65},
    protocol::{ConceptRef, Profile},
    record::{
        RecordKind, RecordPayload, ShortCodeClaim, SignedRecord, UnsignedRecord, encode_record,
        short_code,
    },
};
use libp2p::{
    identity::Keypair,
    kad::{
        ProviderRecord, Record, RecordKey,
        store::{Error as StoreError, RecordStore},
    },
};

fn profile_record(agent_id: AgentId, sequence: u64) -> Record {
    let signed = SignedRecord {
        record: UnsignedRecord {
            payload: RecordPayload::Profile(Profile {
                agent_id,
                sequence,
                capabilities: vec![ConceptRef::RUST],
                avatar: None,
            }),
            sequence,
            issued_at_ms: 1,
            expires_at_ms: 1_000,
        },
        signature: Signature65([0; 65]),
    };
    Record {
        key: identity_record_key(agent_id, RecordKind::Profile).unwrap(),
        value: encode_record(&signed).unwrap(),
        publisher: None,
        expires: None,
    }
}

#[test]
fn record_keys_are_versioned_and_short_code_claim_keys_are_agent_scoped() {
    let first = AgentId([1; 32]);
    let second = AgentId([2; 32]);
    let claim = RecordPayload::ShortCode(ShortCodeClaim {
        agent_id: first,
        code: short_code(first),
    });

    let profile = identity_record_key(first, RecordKind::Profile).unwrap();
    let directory = identity_record_key(first, RecordKind::DeviceDirectory).unwrap();
    let claim_key = identity_record_key(first, RecordKind::ShortCode).unwrap();

    assert_eq!(
        asl_net::dht::record_key_for_payload(&claim).unwrap(),
        claim_key
    );
    assert_ne!(profile, directory);
    assert_ne!(profile, claim_key);
    assert_ne!(
        claim_key,
        identity_record_key(second, RecordKind::ShortCode).unwrap()
    );
    assert_ne!(claim_key, handle_key(short_code(first)).unwrap());
    assert_ne!(
        concept_key(ConceptRef::RUST).unwrap(),
        content_key(Hash32([1; 32]))
    );
}

#[test]
fn store_enforces_record_value_and_sequence_rules() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let agent = AgentId([3; 32]);
    let mut store = BoundedRecordStore::new(peer);
    let first = profile_record(agent, 1);
    store.put(first.clone()).unwrap();

    let mut oversized = first.clone();
    oversized.value.resize(MAX_DHT_VALUE_BYTES + 1, 0);
    assert!(matches!(
        store.put(oversized),
        Err(StoreError::ValueTooLarge)
    ));

    assert!(matches!(
        store.put(profile_record(agent, 0)),
        Err(StoreError::ValueTooLarge)
    ));

    let conflict = profile_record(agent, 1);
    let mut changed_conflict = conflict.clone();
    changed_conflict.value.push(0);
    assert!(matches!(
        store.put(changed_conflict),
        Err(StoreError::ValueTooLarge)
    ));

    store.put(profile_record(agent, 2)).unwrap();
    assert_eq!(store.record_count(), 1);
}

#[test]
fn expired_records_release_store_capacity_on_the_next_write() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let agent = AgentId([6; 32]);
    let mut store = BoundedRecordStore::new(peer);
    let mut expired = profile_record(agent, 1);
    expired.expires = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    store.put(expired).unwrap();
    assert_eq!(store.record_count(), 1);

    store.put(profile_record(AgentId([7; 32]), 1)).unwrap();

    assert_eq!(store.record_count(), 1);
    assert_eq!(
        store.used_bytes(),
        profile_record(AgentId([7; 32]), 1).value.len()
    );
}

#[test]
fn store_caps_the_number_of_distinct_records() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut store = BoundedRecordStore::new(peer);

    for index in 0..MAX_DHT_RECORDS {
        let mut agent = [0; 32];
        agent[..8].copy_from_slice(&(index as u64).to_be_bytes());
        agent[8] = 1;
        store.put(profile_record(AgentId(agent), 1)).unwrap();
    }

    let mut extra = [0; 32];
    extra[..8].copy_from_slice(&(MAX_DHT_RECORDS as u64).to_be_bytes());
    extra[8] = 1;
    assert!(matches!(
        store.put(profile_record(AgentId(extra), 1)),
        Err(StoreError::MaxRecords)
    ));
    assert_eq!(store.record_count(), MAX_DHT_RECORDS);
}

#[test]
fn short_code_handle_is_not_a_single_value_record_key() {
    let code = 1234;
    let handle = handle_key(code).unwrap();
    assert_eq!(handle.as_ref().len(), 32);
    let first = identity_record_key(AgentId([4; 32]), RecordKind::ShortCode).unwrap();
    let second = identity_record_key(AgentId([5; 32]), RecordKind::ShortCode).unwrap();
    assert_ne!(handle, first);
    assert_ne!(first, second);
    assert_eq!(RecordKey::new(&handle.to_vec()), handle);
}

#[test]
fn colliding_handle_lookup_keeps_multiple_provider_candidates() {
    let local_peer = Keypair::generate_ed25519().public().to_peer_id();
    let first = Keypair::generate_ed25519().public().to_peer_id();
    let second = Keypair::generate_ed25519().public().to_peer_id();
    let key = handle_key(1234).unwrap();
    let mut store = BoundedRecordStore::new(local_peer);

    for provider in [first, second] {
        store
            .add_provider(ProviderRecord {
                key: key.clone(),
                provider,
                expires: Some(std::time::Instant::now() + std::time::Duration::from_secs(60)),
                addresses: vec![],
            })
            .unwrap();
    }

    let providers = store.providers(&key);
    assert_eq!(providers.len(), 2);
    assert_ne!(providers[0].provider, providers[1].provider);
}

#[test]
fn expired_provider_records_release_accounting_and_provider_capacity() {
    let local_peer = Keypair::generate_ed25519().public().to_peer_id();
    let first = Keypair::generate_ed25519().public().to_peer_id();
    let second = Keypair::generate_ed25519().public().to_peer_id();
    let first_key = handle_key(1234).unwrap();
    let second_key = handle_key(5678).unwrap();
    let mut store = BoundedRecordStore::new(local_peer);

    store
        .add_provider(ProviderRecord {
            key: first_key.clone(),
            provider: first,
            expires: Some(std::time::Instant::now() - std::time::Duration::from_secs(1)),
            addresses: vec![],
        })
        .unwrap();
    store
        .add_provider(ProviderRecord {
            key: second_key.clone(),
            provider: second,
            expires: None,
            addresses: vec![],
        })
        .unwrap();

    assert!(store.providers(&first_key).is_empty());
    let providers = store.providers(&second_key);
    assert_eq!(providers.len(), 1);
    assert!(providers[0].expires.is_some());
    assert!(store.used_bytes() > 0);
}
