use alloy_primitives::{Address, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_trie::{EMPTY_ROOT_HASH, Nibbles, TrieAccount, proof::verify_proof};
use helios_consensus_core::{
    apply_bootstrap, consensus_spec::MainnetConsensusSpec, types::Bootstrap, verify_bootstrap,
};

fn proof_request_api<P: Provider>(provider: &P) {
    let request = provider.get_proof(Address::ZERO, vec![B256::ZERO]);
    let _request_at_hash = request.block_id(B256::ZERO.into());
}

fn main() {
    let provider = ProviderBuilder::new().connect_mocked_client(Default::default());
    proof_request_api(&provider);
    let _verify = verify_bootstrap::<MainnetConsensusSpec>;
    let _apply = apply_bootstrap::<MainnetConsensusSpec>;
    let _: Option<Bootstrap<MainnetConsensusSpec>> = None;
    let account = TrieAccount::new(0, U256::ZERO, EMPTY_ROOT_HASH, B256::ZERO);
    assert!(!alloy_rlp::encode(account).is_empty());
    verify_proof(EMPTY_ROOT_HASH, Nibbles::unpack(B256::ZERO), None, &[]).unwrap();
    println!("Helios, Alloy get_proof/block hash, and MPT APIs compiled and ran; no RPC sent.");
}
