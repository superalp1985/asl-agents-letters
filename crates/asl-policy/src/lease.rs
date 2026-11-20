use std::collections::HashMap;
use std::sync::Mutex;

use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
};
use rand::{TryRng, rngs::SysRng};

use crate::{AccessOperation, Permit, PolicyService};

pub const LEASE_TTL_MS: u64 = 60_000;
pub const MAX_ACTIVE_LEASES: usize = 4_096;
pub const MAX_ACTIVE_LEASES_PER_PEER: usize = 64;
const MAX_FILE_SIZE: u64 = 68_719_476_736;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    pub lease_id: Hash32,
    pub content_id: Hash32,
    pub expires_at_ms: u64,
    pub file_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseAccess {
    pub content_id: Hash32,
    pub expires_at_ms: u64,
    pub file_size: u64,
}

struct LeaseRecord {
    peer_id: PeerId,
    permit: Permit,
    expires_at_ms: u64,
    file_size: u64,
}

pub struct LeaseManager {
    leases: Mutex<HashMap<Hash32, LeaseRecord>>,
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue<S: PolicyService>(
        &self,
        policy: &S,
        permit: &Permit,
        file_size: u64,
        now_ms: u64,
    ) -> Result<LeaseGrant, AslError> {
        if permit.operation() != AccessOperation::ReadChunk
            || file_size > MAX_FILE_SIZE
            || now_ms >= permit.expires_at_ms()
        {
            return Err(AslError::NotFound);
        }
        policy
            .revalidate(permit, now_ms)
            .map_err(|_| AslError::NotFound)?;
        let peer_id = permit
            .authenticated_device_peer_id()
            .cloned()
            .ok_or(AslError::NotFound)?;
        let expires_at_ms = now_ms
            .checked_add(LEASE_TTL_MS)
            .ok_or(AslError::NotFound)?
            .min(permit.expires_at_ms());
        if expires_at_ms <= now_ms {
            return Err(AslError::NotFound);
        }

        let lease_id = fresh_lease_id()?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| AslError::InvalidPolicyState)?;
        purge_expired(&mut leases, now_ms);
        if leases.len() >= MAX_ACTIVE_LEASES
            || leases
                .values()
                .filter(|lease| lease.peer_id == peer_id)
                .count()
                >= MAX_ACTIVE_LEASES_PER_PEER
        {
            return Err(AslError::QuotaExceeded);
        }
        leases.insert(
            lease_id,
            LeaseRecord {
                peer_id,
                permit: permit.clone(),
                expires_at_ms,
                file_size,
            },
        );
        Ok(LeaseGrant {
            lease_id,
            content_id: permit.content_id(),
            expires_at_ms,
            file_size,
        })
    }

    pub fn validate<S: PolicyService>(
        &self,
        policy: &S,
        lease_id: Hash32,
        peer_id: &PeerId,
        content_id: Hash32,
        now_ms: u64,
    ) -> Result<LeaseAccess, AslError> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| AslError::InvalidPolicyState)?;
        purge_expired(&mut leases, now_ms);
        let lease = leases.get(&lease_id).ok_or(AslError::NotFound)?;
        if lease.peer_id != *peer_id
            || lease.permit.content_id() != content_id
            || now_ms >= lease.expires_at_ms
        {
            return Err(AslError::NotFound);
        }
        policy
            .revalidate(&lease.permit, now_ms)
            .map_err(|_| AslError::NotFound)?;
        Ok(LeaseAccess {
            content_id,
            expires_at_ms: lease.expires_at_ms,
            file_size: lease.file_size,
        })
    }

    pub fn active_count(&self) -> Result<usize, AslError> {
        self.leases
            .lock()
            .map(|leases| leases.len())
            .map_err(|_| AslError::InvalidPolicyState)
    }

    pub fn release(&self, lease_id: Hash32, peer_id: &PeerId) -> Result<(), AslError> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| AslError::InvalidPolicyState)?;
        if leases
            .get(&lease_id)
            .is_some_and(|lease| lease.peer_id == *peer_id)
        {
            leases.remove(&lease_id);
        }
        Ok(())
    }
}

fn purge_expired(leases: &mut HashMap<Hash32, LeaseRecord>, now_ms: u64) {
    leases.retain(|_, lease| lease.expires_at_ms > now_ms);
}

fn fresh_lease_id() -> Result<Hash32, AslError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AslError::InvalidIdentity)?;
        if bytes != [0; 32] {
            return Ok(Hash32(bytes));
        }
    }
    Err(AslError::InvalidIdentity)
}
