use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::MAX_GROUP_MLS_OBJECT_BYTES,
    task::GroupId,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{RoomVersion, sql_number, unsigned};
use crate::{Store, database_error};

const SYNC_WINDOW: i64 = 256;
const EXPIRY_PRUNE_BATCH: i64 = 256;
pub const MLS_SYNC_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsEpochBindings {
    pub base: Hash32,
    pub next: Hash32,
}

impl MlsEpochBindings {
    /// Bind one exact stored step to the local device that seals its snapshot.
    pub fn digest(
        &self,
        local_id: &GroupId,
        wire_id: Hash32,
        local_device: &PeerId,
        epoch_and_expiry: (u64, u64),
        signer: &PeerId,
        ciphertext: &[u8],
    ) -> Hash32 {
        let mut hasher = blake3::Hasher::new_derive_key("ASL-MLS-SYNC-STEP-v1");
        hasher.update(local_id.0.as_bytes());
        hasher.update(wire_id.as_bytes());
        let (base_epoch, expires_at_ms) = epoch_and_expiry;
        hasher.update(&base_epoch.to_be_bytes());
        hasher.update(&expires_at_ms.to_be_bytes());
        hasher.update(self.base.as_bytes());
        hasher.update(self.next.as_bytes());
        for bytes in [local_device.as_bytes(), signer.as_bytes(), ciphertext] {
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        Hash32(*hasher.finalize().as_bytes())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MlsSyncStoredStep {
    pub local_id: GroupId,
    pub base_epoch: u64,
    pub expires_at_ms: u64,
    pub bindings: MlsEpochBindings,
    pub signer: PeerId,
    pub commit: Vec<u8>,
    pub version: RoomVersion,
}

impl Store {
    /// Read a step from an unexpired, contiguous suffix ending at the current
    /// head. Core must verify its seal and authorize the requester separately.
    pub fn mls_sync_step(
        &self,
        wire_id: Hash32,
        base_epoch: u64,
        now_ms: u64,
    ) -> Result<Option<MlsSyncStoredStep>, AslError> {
        let base = sql_number(base_epoch)?;
        let now = sql_number(now_ms)?;
        // Uniqueness per base plus the exact count rules out missing or
        // expired steps; adjacent bindings also have to agree.
        let row = self
            .connection
            .query_row(
                "SELECT s.local_group_id,j.base_binding,j.next_binding,e.sender_peer_id,e.ciphertext,
                        e.expires_at_ms,s.revision,g.mls_epoch,g.membership_epoch,p.revision
                 FROM mls_room_states s
                 JOIN asl_groups g ON g.group_id=s.local_group_id
                 JOIN mls_sync_log j ON j.room_id=s.local_group_id AND j.base_epoch=?2
                 JOIN group_events e ON e.event_id=j.event_id
                 CROSS JOIN policy_state p
                 WHERE s.wire_group_id=?1 AND p.singleton=1
                   AND g.state IN ('needs_sync','active')
                   AND ?2>=g.mls_epoch-?4 AND ?2<g.mls_epoch
                   AND (SELECT count(*) FROM mls_sync_log c
                        JOIN group_events ev ON ev.event_id=c.event_id
                        WHERE c.room_id=j.room_id AND c.base_epoch>=?2 AND c.base_epoch<g.mls_epoch
                          AND c.seq=c.base_epoch+1
                          AND ev.group_id=c.room_id AND ev.mls_epoch=c.base_epoch AND ev.kind='commit'
                          AND ev.created_at_ms<=?3 AND c.expires_at_ms>?3
                          AND ev.expires_at_ms=c.expires_at_ms
                          AND length(ev.ciphertext) BETWEEN 1 AND ?5
                          AND (c.seq=g.mls_epoch OR EXISTS (
                              SELECT 1 FROM mls_sync_log n
                              WHERE n.room_id=c.room_id AND n.base_epoch=c.seq
                                AND n.base_binding=c.next_binding
                          )))=g.mls_epoch-?2",
                params![
                    wire_id.as_bytes(),
                    base,
                    now,
                    SYNC_WINDOW,
                    MAX_GROUP_MLS_OBJECT_BYTES as i64,
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, i64>(7)?,
                        r.get::<_, i64>(8)?,
                        r.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        row.map(
            |(room, base, next, signer, commit, expires, revision, head, membership, policy)| {
                let mut local_id = [0; Id128::LENGTH];
                hex::decode_to_slice(room, &mut local_id).map_err(|_| AslError::InvalidDatabase)?;
                let signer = bs58::decode(signer)
                    .into_vec()
                    .map_err(|_| AslError::InvalidDatabase)?;
                Ok(MlsSyncStoredStep {
                    local_id: GroupId(Id128(local_id)),
                    base_epoch,
                    expires_at_ms: unsigned(expires)?,
                    bindings: MlsEpochBindings {
                        base: Hash32(base.try_into().map_err(|_| AslError::InvalidDatabase)?),
                        next: Hash32(next.try_into().map_err(|_| AslError::InvalidDatabase)?),
                    },
                    signer: PeerId::from_bytes(signer).map_err(|_| AslError::InvalidDatabase)?,
                    commit,
                    version: RoomVersion {
                        revision: unsigned(revision)?,
                        mls_epoch: unsigned(head)?,
                        membership_epoch: unsigned(membership)?,
                        policy_revision: unsigned(policy)?,
                    },
                })
            },
        )
        .transpose()
    }
}

pub(super) fn insert(
    tx: &Transaction<'_>,
    room: &str,
    base: i64,
    next: i64,
    event_id: &str,
    bindings: MlsEpochBindings,
    expires_at_ms: i64,
) -> Result<(), AslError> {
    tx.execute(
        "INSERT INTO mls_sync_log(room_id,base_epoch,seq,base_binding,next_binding,event_id,expires_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            room,
            base,
            next,
            bindings.base.as_bytes(),
            bindings.next.as_bytes(),
            event_id,
            expires_at_ms,
        ],
    )
    .map_err(database_error)?;
    Ok(())
}

pub(super) fn trim_room(tx: &Transaction<'_>, room: &str, head: i64) -> Result<(), AslError> {
    tx.execute(
        "DELETE FROM mls_sync_log WHERE room_id=?1 AND base_epoch<?2",
        params![room, head.saturating_sub(SYNC_WINDOW)],
    )
    .map_err(database_error)?;
    Ok(())
}

pub(super) fn prune_expired(tx: &Transaction<'_>, now: i64) -> Result<(), AslError> {
    // This only removes sync associations; group events keep their
    // existing lifetime and duplicate detection behavior.
    tx.execute(
        "DELETE FROM mls_sync_log WHERE event_id IN (
            SELECT event_id FROM mls_sync_log WHERE expires_at_ms<=?1
            ORDER BY expires_at_ms,event_id LIMIT ?2
         )",
        params![now, EXPIRY_PRUNE_BATCH],
    )
    .map_err(database_error)?;
    Ok(())
}
