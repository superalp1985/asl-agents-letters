use super::*;
use crate::chain::test_support::{BOOTSTRAP_TIME, bootstrapped, proof_fixture, registry_values};

fn resolver() -> EthereumIdentityResolver {
    let (deployment, _, _) = proof_fixture(registry_values(9, 1, 1), 8);
    EthereumIdentityResolver::new(
        bootstrapped(),
        EthereumProofVerifier::new(deployment).unwrap(),
        120,
        2,
    )
    .unwrap()
}

fn verified(sequence: u64, status: u8) -> VerifiedIdentity {
    let (deployment, finalized, proof) = proof_fixture(registry_values(9, sequence, status), 8);
    EthereumProofVerifier::new(deployment)
        .unwrap()
        .verify(&finalized, proof.agent_id, &proof)
        .unwrap()
}

#[test]
fn unknown_and_expired_identities_only_receive_limited_results() {
    let mut resolver = resolver();
    let identity = verified(1, 1);
    let agent = identity.agent_id();
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
    resolver.cache_verified(identity, BOOTSTRAP_TIME).unwrap();
    assert!(matches!(
        resolver.resolve(agent, BOOTSTRAP_TIME + 120),
        IdentityResolution::Verified(_)
    ));
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME + 121),
        IdentityResolution::Limited(LimitedReason::StaleProof)
    );
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME + 1801),
        IdentityResolution::Limited(LimitedReason::ChainUnavailable)
    );
}

#[test]
fn repeated_proof_cannot_extend_cache_lifetime() {
    let mut resolver = resolver();
    let identity = verified(1, 1);
    let agent = identity.agent_id();
    resolver
        .cache_verified(identity.clone(), BOOTSTRAP_TIME)
        .unwrap();
    resolver
        .cache_verified(identity, BOOTSTRAP_TIME + 120)
        .unwrap();
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME + 121),
        IdentityResolution::Limited(LimitedReason::StaleProof)
    );
}

#[test]
fn invalid_rpc_proof_cannot_promote_an_unknown_identity() {
    let mut resolver = resolver();
    let (_, _, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    assert_eq!(
        resolver.accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME),
        Err(ChainError::WrongContext)
    );
    assert_eq!(
        resolver.resolve(proof.agent_id, BOOTSTRAP_TIME),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
}

#[test]
fn sequence_rollback_and_same_sequence_controller_changes_are_rejected() {
    let mut resolver = resolver();
    let mut current = verified(2, 1);
    current.finalized.block_number += 1;
    let agent = current.agent_id();
    resolver
        .cache_verified(current.clone(), BOOTSTRAP_TIME)
        .unwrap();
    assert_eq!(
        resolver.cache_verified(verified(1, 1), BOOTSTRAP_TIME),
        Err(ChainError::Rollback)
    );
    let mut changed = current;
    changed.state.controller = [3; 20];
    changed.finalized.block_number += 1;
    assert_eq!(
        resolver.cache_verified(changed, BOOTSTRAP_TIME),
        Err(ChainError::Rollback)
    );
    assert!(matches!(
        resolver.resolve(agent, BOOTSTRAP_TIME),
        IdentityResolution::Verified(identity) if identity.state().sequence == 2
    ));
}

#[test]
fn revocation_stays_limited_and_cannot_be_replaced_with_active_state() {
    let mut resolver = resolver();
    let revoked = verified(2, 2);
    let agent = revoked.agent_id();
    resolver.cache_verified(revoked, BOOTSTRAP_TIME).unwrap();
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
    let mut active = verified(3, 1);
    active.finalized.block_number += 1;
    assert_eq!(
        resolver.cache_verified(active, BOOTSTRAP_TIME),
        Err(ChainError::Rollback)
    );
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME + 1_000_000),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
}

#[test]
fn cache_eviction_only_downgrades_the_evicted_identity() {
    let mut resolver = resolver();
    resolver.capacity = 1;
    let revoked = verified(2, 2);
    let agent = revoked.agent_id();
    resolver.cache_verified(revoked, BOOTSTRAP_TIME).unwrap();
    let mut other = verified(1, 1);
    other.agent_id = AgentId([99; 32]);
    resolver.cache_verified(other, BOOTSTRAP_TIME + 1).unwrap();
    assert_eq!(resolver.cache.len(), 1);
    assert_eq!(
        resolver.resolve(agent, BOOTSTRAP_TIME),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
}

#[test]
fn expired_negative_cache_entries_do_not_block_new_identities() {
    let mut resolver = resolver();
    resolver.capacity = 1;
    let (deployment, finalized, proof) = proof_fixture([[0; 32]; 3], 8);
    let unregistered = EthereumProofVerifier::new(deployment)
        .unwrap()
        .verify(&finalized, proof.agent_id, &proof)
        .unwrap();
    resolver
        .cache_verified(unregistered, BOOTSTRAP_TIME)
        .unwrap();
    let mut new_identity = verified(1, 1);
    new_identity.agent_id = AgentId([99; 32]);
    new_identity.finalized.timestamp_secs += 121;
    let new_agent = new_identity.agent_id;
    resolver
        .cache_verified(new_identity, BOOTSTRAP_TIME + 121)
        .unwrap();
    assert_eq!(resolver.cache.len(), 1);
    assert!(matches!(
        resolver.resolve(new_agent, BOOTSTRAP_TIME + 121),
        IdentityResolution::Verified(_)
    ));
}

#[test]
fn live_cache_evicts_the_least_recently_used_identity() {
    let mut resolver = resolver();
    let first = verified(1, 1);
    let first_id = first.agent_id;
    let mut second = first.clone();
    second.agent_id = AgentId([98; 32]);
    let second_id = second.agent_id;
    let mut third = first.clone();
    third.agent_id = AgentId([99; 32]);
    resolver.cache_verified(first, BOOTSTRAP_TIME).unwrap();
    resolver.cache_verified(second, BOOTSTRAP_TIME + 1).unwrap();
    resolver.resolve(first_id, BOOTSTRAP_TIME + 2);
    resolver.cache_verified(third, BOOTSTRAP_TIME + 3).unwrap();
    assert!(matches!(
        resolver.resolve(first_id, BOOTSTRAP_TIME + 3),
        IdentityResolution::Verified(_)
    ));
    assert_eq!(
        resolver.resolve(second_id, BOOTSTRAP_TIME + 3),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
}
