use std::collections::HashSet;

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, PeerId},
    protocol::{PairingInvite, validate_pairing_note},
    record::short_code,
};
use libp2p::kad::RecordKey;

pub const MAX_SHORT_CODE_CANDIDATES: usize = 20;
const TRANSCRIPT_DOMAIN: &[u8] = b"ASL-PAIR-TRANSCRIPT-v1\0";

/// A persistent short code identifies a discovery bucket, never an identity.
/// Call `matching_admitted_peers` only with AgentId/PeerId pairs that already
/// passed CoreAdmission and the local finalized-chain resolver.
pub struct ShortCodeLookup {
    code: u64,
    peers: HashSet<PeerId>,
}

impl ShortCodeLookup {
    pub fn new(code: u64) -> Result<Self, AslError> {
        let _ = crate::dht::handle_key(code)?;
        Ok(Self {
            code,
            peers: HashSet::new(),
        })
    }

    pub fn key(&self) -> Result<RecordKey, AslError> {
        crate::dht::handle_key(self.code)
    }

    pub fn record_provider(&mut self, peer: PeerId) -> bool {
        if self.peers.contains(&peer) {
            return true;
        }
        if self.peers.len() >= MAX_SHORT_CODE_CANDIDATES {
            return false;
        }
        self.peers.insert(peer)
    }

    pub fn candidate_peers(&self) -> Vec<PeerId> {
        let mut peers: Vec<_> = self.peers.iter().cloned().collect();
        peers.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        peers
    }

    pub fn matching_admitted_peers(
        &self,
        admitted: impl IntoIterator<Item = (AgentId, PeerId)>,
    ) -> Vec<(AgentId, PeerId)> {
        let mut matches: Vec<_> = admitted
            .into_iter()
            .filter(|(agent, peer)| self.peers.contains(peer) && short_code(*agent) == self.code)
            .collect();
        matches.sort_by(|left, right| {
            left.0
                .as_bytes()
                .cmp(right.0.as_bytes())
                .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
        });
        matches.dedup();
        matches
    }
}

/// Binds a signed invitation response to the target-specific invitation and
/// the authenticated device pair used for that exchange.
pub fn transcript_hash(
    invite: &PairingInvite,
    inviter_peer: &PeerId,
    target_peer: &PeerId,
) -> Result<Hash32, AslError> {
    if invite.invite_id.0 == [0; 16]
        || invite.inviter == invite.target
        || invite.nonce.0 == [0; 32]
        || inviter_peer.as_bytes().len() > u16::MAX as usize
        || target_peer.as_bytes().len() > u16::MAX as usize
    {
        return Err(AslError::InvalidMessage);
    }
    validate_pairing_note(&invite.note)?;
    let note_length = u16::try_from(invite.note.len()).map_err(|_| AslError::InvalidMessage)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update(invite.invite_id.as_bytes());
    hasher.update(invite.inviter.as_bytes());
    hasher.update(invite.target.as_bytes());
    hasher.update(&invite.expires_at_ms.to_be_bytes());
    hasher.update(invite.nonce.as_bytes());
    hasher.update(&note_length.to_be_bytes());
    hasher.update(invite.note.as_bytes());
    hasher.update(invite.signature.as_bytes());
    update_peer(&mut hasher, inviter_peer);
    update_peer(&mut hasher, target_peer);
    Ok(Hash32(*hasher.finalize().as_bytes()))
}

fn update_peer(hasher: &mut blake3::Hasher, peer: &PeerId) {
    hasher.update(&(peer.as_bytes().len() as u16).to_be_bytes());
    hasher.update(peer.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn peer(seed: u8) -> PeerId {
        let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn agent(seed: u8) -> AgentId {
        AgentId([seed; 32])
    }

    #[test]
    fn short_code_lookup_keeps_multiple_candidates_and_filters_after_admission() {
        let wanted = agent(8);
        let code = short_code(wanted);
        let matching_peer = peer(1);
        let other_candidate = peer(2);
        let mut lookup = ShortCodeLookup::new(code).unwrap();

        assert!(lookup.record_provider(other_candidate.clone()));
        assert!(lookup.record_provider(matching_peer.clone()));
        assert!(lookup.record_provider(matching_peer.clone()));
        assert_eq!(lookup.candidate_peers().len(), 2);

        let matches = lookup.matching_admitted_peers([
            (agent(9), other_candidate),
            (wanted, matching_peer.clone()),
            (wanted, matching_peer),
        ]);
        assert_eq!(matches, [(wanted, peer(1))]);
    }

    #[test]
    fn short_code_lookup_caps_unique_provider_candidates() {
        let mut lookup = ShortCodeLookup::new(0).unwrap();
        for seed in 1..=MAX_SHORT_CODE_CANDIDATES as u8 {
            assert!(lookup.record_provider(peer(seed)));
        }
        assert!(!lookup.record_provider(peer(100)));
        assert_eq!(lookup.candidate_peers().len(), MAX_SHORT_CODE_CANDIDATES);
    }
}
