use asl_types::{error::AslError, ids::PeerId};
use rusqlite::TransactionBehavior;

use super::{
    MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate, RoomVersion,
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
    /// Advance a paused room's ratchet and journal its ciphertext together.
    /// This is not an authorization or delivery operation.
    pub fn commit_verified_mls_application(
        &mut self,
        update: MlsRoomUpdate<'_>,
        authority: MlsApplicationAuthority<'_>,
        mut current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
        if !update
            .event
            .as_ref()
            .is_some_and(|event| matches!(event.kind, MlsJournalKind::Application(_)))
            || member_ids(authority.members)? != update.members.iter().map(peer_text).collect()
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
        Ok(version)
    }
}
