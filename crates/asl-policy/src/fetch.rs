use asl_types::{
    error::AslError,
    ids::{Id128, PeerId},
    protocol::{FetchGrant, FetchRequest},
};
use rand::{TryRng, rngs::SysRng};

use crate::{LeaseAccess, LeaseManager, Permit, PolicyService};

pub fn issue_fetch_grant<S: PolicyService>(
    policy: &S,
    leases: &LeaseManager,
    peer_id: &PeerId,
    request: &FetchRequest,
    permit: &Permit,
    file_size: u64,
    now_ms: u64,
) -> Result<FetchGrant, AslError> {
    if permit.authenticated_device_peer_id() != Some(peer_id)
        || permit.content_id() != request.content_id
    {
        return Err(AslError::NotFound);
    }
    let lease = leases
        .issue(policy, permit, file_size, now_ms)
        .map_err(|_| AslError::NotFound)?;
    Ok(FetchGrant {
        message_id: fresh_message_id()?,
        content_id: lease.content_id,
        lease_id: lease.lease_id,
        expires_at_ms: lease.expires_at_ms,
        file_size: lease.file_size,
    })
}

pub fn validate_fetch_grant<S: PolicyService>(
    policy: &S,
    leases: &LeaseManager,
    peer_id: &PeerId,
    grant: &FetchGrant,
    now_ms: u64,
) -> Result<LeaseAccess, AslError> {
    leases.validate(policy, grant.lease_id, peer_id, grant.content_id, now_ms)
}

fn fresh_message_id() -> Result<Id128, AslError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AslError::InvalidIdentity)?;
        if bytes != [0; 16] {
            return Ok(Id128(bytes));
        }
    }
    Err(AslError::InvalidIdentity)
}
