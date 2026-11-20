use std::collections::{HashMap, HashSet};

use asl_types::{error::AslError, ids::PeerId, manifest::CHUNK_SIZE};

const ASSIGNMENT_TIMEOUT_MS: u64 = 10_000;
pub const MAX_ACTIVE_SOURCES: usize = 4;
const MAX_ACTIVE_PER_SOURCE: u8 = 2;
const MAX_ACTIVE_REQUESTS: usize = MAX_ACTIVE_SOURCES * MAX_ACTIVE_PER_SOURCE as usize;
const MAX_BAD_HASHES: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    Timeout,
    Disconnected,
    BadHash,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkAssignment {
    pub peer_id: PeerId,
    pub index: u32,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedChunk {
    pub index: u32,
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
}

pub trait ChunkScheduler {
    fn next(&mut self, now_ms: u64) -> Vec<ChunkAssignment>;
    fn received(
        &mut self,
        peer_id: &PeerId,
        index: u32,
        bytes: &[u8],
    ) -> Result<VerifiedChunk, AslError>;
    fn mark_durable(&mut self, indexes: &[u32]) -> Result<(), AslError>;
    fn failed(&mut self, peer_id: &PeerId, index: u32, reason: FailureKind);
}

#[derive(Clone, Debug)]
enum ChunkState {
    Missing,
    Assigned { peer_id: PeerId, deadline_ms: u64 },
    Buffered,
    Durable,
}

pub struct Scheduler {
    file_size: u64,
    expected_hashes: Vec<[u8; 32]>,
    states: Vec<ChunkState>,
    candidates: Vec<PeerId>,
    active_by_peer: HashMap<PeerId, u8>,
    bad_hashes: HashMap<PeerId, u8>,
    disabled: HashSet<PeerId>,
    next_candidate: usize,
}

impl Scheduler {
    pub fn new(
        file_size: u64,
        expected_hashes: Vec<[u8; 32]>,
        candidates: impl IntoIterator<Item = PeerId>,
    ) -> Result<Self, AslError> {
        let expected_count = if file_size == 0 {
            0
        } else {
            usize::try_from(
                file_size
                    .checked_add(u64::from(CHUNK_SIZE) - 1)
                    .ok_or(AslError::InvalidMessage)?
                    / u64::from(CHUNK_SIZE),
            )
            .map_err(|_| AslError::InvalidMessage)?
        };
        if expected_hashes.len() != expected_count {
            return Err(AslError::InvalidMessage);
        }
        let mut unique = HashSet::new();
        let candidates = candidates
            .into_iter()
            .filter(|peer| unique.insert(peer.clone()))
            .take(MAX_ACTIVE_SOURCES)
            .collect::<Vec<_>>();
        Ok(Self {
            file_size,
            states: vec![ChunkState::Missing; expected_hashes.len()],
            expected_hashes,
            candidates,
            active_by_peer: HashMap::new(),
            bad_hashes: HashMap::new(),
            disabled: HashSet::new(),
            next_candidate: 0,
        })
    }

    pub fn from_durable(
        file_size: u64,
        expected_hashes: Vec<[u8; 32]>,
        candidates: impl IntoIterator<Item = PeerId>,
        durable_indexes: &[u32],
    ) -> Result<Self, AslError> {
        let mut scheduler = Self::new(file_size, expected_hashes, candidates)?;
        for &index in durable_indexes {
            let state = scheduler
                .states
                .get_mut(index as usize)
                .ok_or(AslError::InvalidMessage)?;
            *state = ChunkState::Durable;
        }
        Ok(scheduler)
    }

    pub fn discard_buffered(&mut self, index: u32) -> Result<(), AslError> {
        let state = self
            .states
            .get_mut(index as usize)
            .ok_or(AslError::NotFound)?;
        if !matches!(state, ChunkState::Buffered) {
            return Err(AslError::InvalidMessage);
        }
        *state = ChunkState::Missing;
        Ok(())
    }

    pub fn durable_count(&self) -> usize {
        self.states
            .iter()
            .filter(|state| matches!(state, ChunkState::Durable))
            .count()
    }

    pub fn disabled_peers(&self) -> &HashSet<PeerId> {
        &self.disabled
    }

    fn expire_assignments(&mut self, now_ms: u64) {
        for state in &mut self.states {
            let expired = matches!(
                state,
                ChunkState::Assigned { deadline_ms, .. } if *deadline_ms <= now_ms
            );
            if expired {
                if let ChunkState::Assigned { peer_id, .. } = state {
                    decrement_active(&mut self.active_by_peer, peer_id);
                }
                *state = ChunkState::Missing;
            }
        }
    }

    fn next_peer(&mut self, eligible: &impl Fn(&PeerId) -> bool) -> Option<PeerId> {
        for _ in 0..self.candidates.len() {
            let index = self.next_candidate % self.candidates.len();
            self.next_candidate = self.next_candidate.wrapping_add(1);
            let peer = self.candidates[index].clone();
            if !eligible(&peer)
                || self.disabled.contains(&peer)
                || self.active_by_peer.get(&peer).copied().unwrap_or(0) >= MAX_ACTIVE_PER_SOURCE
            {
                continue;
            }
            return Some(peer);
        }
        None
    }

    fn expected_length(&self, index: u32) -> Result<usize, AslError> {
        let offset = u64::from(index)
            .checked_mul(u64::from(CHUNK_SIZE))
            .ok_or(AslError::InvalidMessage)?;
        let length = self
            .file_size
            .checked_sub(offset)
            .ok_or(AslError::InvalidMessage)?
            .min(u64::from(CHUNK_SIZE));
        usize::try_from(length).map_err(|_| AslError::InvalidMessage)
    }
    pub fn next_where(
        &mut self,
        now_ms: u64,
        eligible: impl Fn(&PeerId) -> bool,
    ) -> Vec<ChunkAssignment> {
        self.expire_assignments(now_ms);
        let mut assignments = Vec::new();
        let active_count: usize = self
            .active_by_peer
            .values()
            .map(|count| usize::from(*count))
            .sum();
        let capacity = MAX_ACTIVE_REQUESTS.saturating_sub(active_count);
        for index in 0..self.states.len() {
            if assignments.len() >= capacity {
                break;
            }
            if !matches!(self.states[index], ChunkState::Missing) {
                continue;
            }
            let Some(peer_id) = self.next_peer(&eligible) else {
                break;
            };
            let deadline_ms = now_ms.saturating_add(ASSIGNMENT_TIMEOUT_MS);
            self.states[index] = ChunkState::Assigned {
                peer_id: peer_id.clone(),
                deadline_ms,
            };
            *self.active_by_peer.entry(peer_id.clone()).or_default() += 1;
            assignments.push(ChunkAssignment {
                peer_id,
                index: u32::try_from(index).expect("chunk index is bounded by manifest"),
                deadline_ms,
            });
        }
        assignments
    }
    /// Verify the borrowed network buffer without making a second payload copy.
    pub fn verify_and_buffer(
        &mut self,
        peer_id: &PeerId,
        index: u32,
        bytes: &[u8],
    ) -> Result<[u8; 32], AslError> {
        let index_usize = usize::try_from(index).map_err(|_| AslError::InvalidMessage)?;
        let Some(state) = self.states.get(index_usize) else {
            return Err(AslError::NotFound);
        };
        if !matches!(
            state,
            ChunkState::Assigned {
                peer_id: assigned_peer,
                ..
            } if assigned_peer == peer_id
        ) {
            return Err(AslError::NotFound);
        }
        if bytes.len() != self.expected_length(index)? {
            return Err(AslError::InvalidMessage);
        }
        let hash = *blake3::hash(bytes).as_bytes();
        if hash != self.expected_hashes[index_usize] {
            self.failed(peer_id, index, FailureKind::BadHash);
            return Err(AslError::InvalidMessage);
        }
        decrement_active(&mut self.active_by_peer, peer_id);
        self.states[index_usize] = ChunkState::Buffered;
        Ok(hash)
    }
}

impl ChunkScheduler for Scheduler {
    fn next(&mut self, now_ms: u64) -> Vec<ChunkAssignment> {
        self.next_where(now_ms, |_| true)
    }

    fn received(
        &mut self,
        peer_id: &PeerId,
        index: u32,
        bytes: &[u8],
    ) -> Result<VerifiedChunk, AslError> {
        let hash = self.verify_and_buffer(peer_id, index, bytes)?;
        Ok(VerifiedChunk {
            index,
            hash,
            bytes: bytes.to_vec(),
        })
    }

    fn mark_durable(&mut self, indexes: &[u32]) -> Result<(), AslError> {
        for index in indexes {
            let state = self
                .states
                .get_mut(usize::try_from(*index).map_err(|_| AslError::NotFound)?)
                .ok_or(AslError::NotFound)?;
            if !matches!(state, ChunkState::Buffered) {
                return Err(AslError::InvalidMessage);
            }
            *state = ChunkState::Durable;
        }
        Ok(())
    }

    fn failed(&mut self, peer_id: &PeerId, index: u32, reason: FailureKind) {
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        let Some(state) = self.states.get(index) else {
            return;
        };
        if !matches!(
            state,
            ChunkState::Assigned {
                peer_id: assigned_peer,
                ..
            } if assigned_peer == peer_id
        ) {
            return;
        }
        decrement_active(&mut self.active_by_peer, peer_id);
        if reason == FailureKind::BadHash {
            let bad_hashes = self.bad_hashes.entry(peer_id.clone()).or_default();
            *bad_hashes = bad_hashes.saturating_add(1);
            if *bad_hashes >= MAX_BAD_HASHES {
                self.disabled.insert(peer_id.clone());
            }
        }
        self.states[index] = ChunkState::Missing;
    }
}

fn decrement_active(active: &mut HashMap<PeerId, u8>, peer_id: &PeerId) {
    if let Some(count) = active.get_mut(peer_id) {
        *count -= 1;
        if *count == 0 {
            active.remove(peer_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(index: u8) -> PeerId {
        let mut bytes = vec![0, 36, 8, 1, 18, 32];
        bytes.extend_from_slice(&[index; 32]);
        PeerId::from_bytes(bytes).unwrap()
    }

    fn scheduler(file_size: u64, peers: &[u8]) -> (Scheduler, Vec<Vec<u8>>) {
        let mut bytes = Vec::new();
        let count = if file_size == 0 {
            0
        } else {
            (file_size + u64::from(CHUNK_SIZE) - 1) / u64::from(CHUNK_SIZE)
        };
        let mut hashes = Vec::new();
        for index in 0..count {
            let length = file_size
                .saturating_sub(index * u64::from(CHUNK_SIZE))
                .min(u64::from(CHUNK_SIZE)) as usize;
            let chunk = vec![index as u8; length];
            hashes.push(*blake3::hash(&chunk).as_bytes());
            bytes.push(chunk);
        }
        (
            Scheduler::new(file_size, hashes, peers.iter().copied().map(peer)).unwrap(),
            bytes,
        )
    }

    #[test]
    fn caps_assignments_per_source_and_total() {
        let (mut scheduler, _) = scheduler(u64::from(CHUNK_SIZE) * 8, &[1, 2, 3, 4, 5]);
        let assignments = scheduler.next(1_000);
        assert_eq!(assignments.len(), 8);
        for source in 1..=4 {
            assert_eq!(
                assignments
                    .iter()
                    .filter(|assignment| assignment.peer_id == peer(source))
                    .count(),
                2
            );
        }
    }

    #[test]
    fn timeout_returns_the_chunk_to_missing() {
        let (mut scheduler, _) = scheduler(u64::from(CHUNK_SIZE), &[1, 2]);
        let first = scheduler.next(1_000);
        assert_eq!(first.len(), 1);
        let second = scheduler.next(11_000);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].index, first[0].index);
    }

    #[test]
    fn three_bad_hashes_disable_a_source() {
        let (mut scheduler, _) = scheduler(u64::from(CHUNK_SIZE), &[1]);
        for now in [1_000, 12_000, 23_000] {
            let assignment = scheduler.next(now);
            assert_eq!(assignment.len(), 1);
            scheduler.failed(&peer(1), assignment[0].index, FailureKind::BadHash);
        }
        assert!(scheduler.disabled_peers().contains(&peer(1)));
        assert!(scheduler.next(34_000).is_empty());
    }

    #[test]
    fn verified_chunk_is_not_completed_twice() {
        let (mut scheduler, chunks) = scheduler(u64::from(CHUNK_SIZE), &[1]);
        let assignment = scheduler.next(1_000).pop().unwrap();
        let verified = scheduler
            .received(&assignment.peer_id, assignment.index, &chunks[0])
            .unwrap();
        assert_eq!(verified.index, 0);
        assert!(
            scheduler
                .received(&assignment.peer_id, assignment.index, &chunks[0])
                .is_err()
        );
        scheduler.mark_durable(&[0]).unwrap();
        assert_eq!(scheduler.durable_count(), 1);
        assert!(scheduler.mark_durable(&[0]).is_err());
    }

    #[test]
    fn resumed_scheduler_skips_durable_blocks_and_retries_an_unsaved_buffer() {
        let blocks = [vec![7; CHUNK_SIZE as usize], vec![8; 3]];
        let hashes = blocks
            .iter()
            .map(|block| *blake3::hash(block).as_bytes())
            .collect();
        let mut scheduler =
            Scheduler::from_durable(u64::from(CHUNK_SIZE) + 3, hashes, [peer(1)], &[0]).unwrap();
        assert_eq!(scheduler.durable_count(), 1);
        let assignment = scheduler.next(1_000).pop().unwrap();
        assert_eq!(assignment.index, 1);
        scheduler
            .received(&assignment.peer_id, assignment.index, &blocks[1])
            .unwrap();
        assert!(scheduler.next(1_001).is_empty());
        scheduler.discard_buffered(1).unwrap();
        assert_eq!(
            scheduler
                .next(1_002)
                .iter()
                .map(|assignment| assignment.index)
                .collect::<Vec<_>>(),
            [1]
        );
    }
}
