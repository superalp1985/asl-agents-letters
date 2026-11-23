use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
};
use rusqlite::TransactionBehavior;

use super::{
    GroupInboundPolicy, MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate, RoomVersion,
    recovery::require_member,
    sql_number,
    sync_authority::{member_ids, room_version},
    transition::{commit_candidate, peer_text},
};
use crate::{Store, database_error};

pub struct MlsApplicationAuthority<'a> {
    pub creator: &'a PeerId,
    pub members: &'a [MlsMemberEvidence],
    pub chain_id: u64,
}

impl Store {
    /// Serialize bounded, nonblocking Core-to-Net enqueue with competing
    /// room and identity writes. The ratchet must already be committed.
    pub fn with_mls_application_dispatch<T>(
        &mut self,
        wire_id: Hash32,
        version: RoomVersion,
        authority: MlsApplicationAuthority<'_>,
        now_ms: u64,
        automatic_reply: bool,
        enqueue: impl FnOnce() -> T,
    ) -> Result<T, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if room_version(&tx, wire_id, authority.creator)? != version {
            return Err(AslError::PolicyVersionConflict);
        }
        if automatic_reply && !super::GroupInboundPolicy::read(&tx)?.answer_enabled {
            return Err(AslError::PolicyDenied);
        }
        for member in authority.members {
            require_member(&tx, member, authority.chain_id, now_ms)?;
        }
        let result = enqueue();
        drop(tx);
        Ok(result)
    }

    /// Advance a paused room's ratchet and journal its ciphertext together.
    /// Return the browse flag for incoming messages as observed at commit,
    /// independent of retention. This is not authorization to send a reply.
    pub fn commit_verified_mls_application(
        &mut self,
        update: MlsRoomUpdate<'_>,
        authority: MlsApplicationAuthority<'_>,
        mut current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<(RoomVersion, bool), AslError> {
        if !update.event.as_ref().is_some_and(|event| {
            matches!(
                event.kind,
                MlsJournalKind::Application(_) | MlsJournalKind::ReceivedApplication(..)
            )
        }) || member_ids(authority.members)? != update.members.iter().map(peer_text).collect()
        {
            return Err(AslError::InvalidPolicyState);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if room_version(&tx, update.wire_id, authority.creator)? != update.expected {
            return Err(AslError::PolicyVersionConflict);
        }
        let now = current_time()?;
        for member in authority.members {
            require_member(&tx, member, authority.chain_id, now)?;
        }
        let browse_enabled = matches!(
            update.event.as_ref().map(|event| event.kind),
            Some(MlsJournalKind::ReceivedApplication(..))
        ) && GroupInboundPolicy::read(&tx)?.browse_enabled;
        let version = commit_candidate(&tx, update, None, sql_number(now)?)?;
        let now = current_time()?;
        if authority
            .members
            .iter()
            .any(|member| now >= member.certificate.expires_at_ms)
        {
            return Err(AslError::ExpiredMessage);
        }
        tx.commit().map_err(database_error)?;
        Ok((version, browse_enabled))
    }
}
