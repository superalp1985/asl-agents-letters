use super::*;
use crate::chain::test_support::{proof_fixture, registry_values};

#[test]
fn verifies_account_and_all_registry_slots_for_active_and_revoked_entries() {
    for (status, expected) in [(1, RegistryStatus::Active), (2, RegistryStatus::Revoked)] {
        let (deployment, finalized, mut proof) = proof_fixture(registry_values(9, 17, status), 8);
        proof.storage.reverse();
        let verified = EthereumProofVerifier::new(deployment)
            .unwrap()
            .verify(&finalized, proof.agent_id, &proof)
            .unwrap();
        assert_eq!(verified.state().controller, [9; 20]);
        assert_eq!(verified.state().sequence, 17);
        assert_eq!(verified.state().state_commitment, [42; 32]);
        assert_eq!(verified.state().status, expected);
    }
}

#[test]
fn verifies_zero_slot_exclusion_and_unregistered_identity() {
    for values in [[[0; 32]; 3], {
        let mut values = registry_values(9, 1, 1);
        values[1] = [0; 32];
        values
    }] {
        let (deployment, finalized, proof) = proof_fixture(values, 8);
        let verified = EthereumProofVerifier::new(deployment)
            .unwrap()
            .verify(&finalized, proof.agent_id, &proof)
            .unwrap();
        assert_eq!(verified.state().state_commitment, [0; 32]);
        if values == [[0; 32]; 3] {
            assert_eq!(verified.state().status, RegistryStatus::Unregistered);
        }
    }
}

#[test]
fn deployment_address_and_code_hash_are_configuration_not_constants() {
    for variant in [8, 19] {
        let (deployment, finalized, proof) = proof_fixture(registry_values(9, 1, 1), variant);
        let mut wrong_deployment = deployment;
        wrong_deployment.runtime_code_hash = [99; 32];
        assert_eq!(
            EthereumProofVerifier::new(wrong_deployment)
                .unwrap()
                .verify(&finalized, proof.agent_id, &proof),
            Err(ChainError::WrongCodeHash)
        );
        assert!(
            EthereumProofVerifier::new(deployment)
                .unwrap()
                .verify(&finalized, proof.agent_id, &proof)
                .is_ok()
        );
    }
}

#[test]
fn rejects_wrong_agent_chain_registry_and_finalized_block_metadata() {
    let (deployment, finalized, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    let verifier = EthereumProofVerifier::new(deployment).unwrap();
    let mut mutations = vec![proof.clone(); 7];
    mutations[0].agent_id = AgentId([4; 32]);
    mutations[1].chain_id += 1;
    mutations[2].registry_address = [4; 20];
    mutations[3].block_number += 1;
    mutations[4].block_hash = [4; 32];
    mutations[5].state_root = [4; 32];
    mutations[6].version = 2;
    for mutated in mutations {
        assert_eq!(
            verifier.verify(&finalized, proof.agent_id, &mutated),
            Err(ChainError::WrongContext)
        );
    }
}

#[test]
fn rejects_corrupt_truncated_and_incorrect_account_or_storage_proofs() {
    let (deployment, finalized, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    let verifier = EthereumProofVerifier::new(deployment).unwrap();
    let mut mutations = vec![proof.clone(); 6];
    mutations[0].account.nodes[0][0] ^= 1;
    mutations[1].account.nonce += 1;
    mutations[2].account.storage_root = [4; 32];
    mutations[3].storage[0].nodes.pop();
    mutations[4].storage[1].value = [4; 32];
    mutations[5].account.nodes.clear();
    for mutated in mutations {
        assert_eq!(
            verifier.verify(&finalized, proof.agent_id, &mutated),
            Err(ChainError::InvalidProof)
        );
    }
}

#[test]
fn rejects_missing_duplicate_and_unexpected_slots() {
    let (deployment, finalized, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    let verifier = EthereumProofVerifier::new(deployment).unwrap();
    let mut mutations = vec![proof.clone(); 3];
    mutations[0].storage.pop();
    mutations[1].storage[1] = mutations[1].storage[0].clone();
    mutations[2].storage[2].slot = [4; 32];
    for mutated in mutations {
        assert_eq!(
            verifier.verify(&finalized, proof.agent_id, &mutated),
            Err(ChainError::WrongContext)
        );
    }
}

#[test]
fn rejects_noncanonical_registry_padding_and_impossible_status() {
    let base = registry_values(9, 1, 1);
    let mut invalid_values = [base; 5];
    invalid_values[0][0][0] = 1;
    invalid_values[1][2][0] = 1;
    invalid_values[2][2][23] = 3;
    invalid_values[3][2][24..].fill(0);
    invalid_values[4][2][23] = 0;
    for values in invalid_values {
        let (deployment, finalized, proof) = proof_fixture(values, 8);
        assert_eq!(
            EthereumProofVerifier::new(deployment).unwrap().verify(
                &finalized,
                proof.agent_id,
                &proof
            ),
            Err(ChainError::InvalidRegistryState)
        );
    }
}

#[test]
fn checks_path_node_slot_and_total_byte_limits_before_verification() {
    let (deployment, finalized, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    let verifier = EthereumProofVerifier::new(deployment).unwrap();
    let mut mutations = vec![proof.clone(); 4];
    mutations[0].account.nodes = vec![vec![0; 1]; 33];
    mutations[1].account.nodes = vec![vec![0; 2049]];
    mutations[2].storage = vec![proof.storage[0].clone(); 9];
    mutations[3].account.nodes = vec![vec![0; 2048]; 32];
    for path in &mut mutations[3].storage {
        path.nodes = vec![vec![0; 2048]; 32];
    }
    for mutated in mutations {
        assert_eq!(
            verifier.verify(&finalized, proof.agent_id, &mutated),
            Err(ChainError::ProofTooLarge)
        );
    }
}
