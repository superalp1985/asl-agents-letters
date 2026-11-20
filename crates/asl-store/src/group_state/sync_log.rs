use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::MAX_GROUP_MLS_OBJECT_BYTES,
    task::GroupId,
};
use rusqlite::{Connection, Transaction, params};

use super::{RoomVersion, sql_number, unsigned};
use crate::{Store, database_error};

pub const MLS_SYNC_MAX_STEPS: u64 = 256;
const SYNC_WINDOW: i64 = MLS_SYNC_MAX_STEPS as i64;
const EXPIRY_PRUNE_BATCH: i64 = 256;
// A byte needs fewer than two Base58 digits even at maximum width.
const MAX_SIGNER_TEXT_BYTES: usize = 2 * PeerId::MAX_BYTES;
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
    /// head. This is a local inspection API, not an authorization decision.
    pub fn mls_sync_step(
        &self,
        wire_id: Hash32,
        base_epoch: u64,
        now_ms: u64,
    ) -> Result<Option<MlsSyncStoredStep>, AslError> {
        read_step(
            &self.connection,
            wire_id,
            base_epoch,
            None,
            || Ok(now_ms),
            |_| Ok(true),
        )
    }
}

pub(super) fn read_step(
    connection: &Connection,
    wire_id: Hash32,
    base_epoch: u64,
    head_binding: Option<Hash32>,
    current_time: impl Fn() -> Result<u64, AslError>,
    mut verify: impl FnMut(&MlsSyncStoredStep) -> Result<bool, AslError>,
) -> Result<Option<MlsSyncStoredStep>, AslError> {
    let base = sql_number(base_epoch)?;
    let now = sql_number(current_time()?)?;
    // Stream one bounded suffix in order, keeping just the requested step.
    let mut statement = connection
        .prepare(
            "SELECT s.local_group_id,j.base_epoch,j.base_binding,j.next_binding,
                        e.sender_peer_id,e.ciphertext,e.expires_at_ms,
                        s.revision,g.mls_epoch,g.membership_epoch,p.revision
                 FROM mls_room_states s
                 JOIN asl_groups g ON g.group_id=s.local_group_id
                 JOIN mls_sync_log j ON j.room_id=s.local_group_id
                 JOIN group_events e ON e.event_id=j.event_id
                 CROSS JOIN policy_state p
                 WHERE s.wire_group_id=?1 AND p.singleton=1
                   AND g.state IN ('needs_sync','active')
                   AND ?2>=g.mls_epoch-?4 AND j.base_epoch>=?2 AND j.base_epoch<g.mls_epoch
                   AND j.seq=j.base_epoch+1
                   AND e.group_id=j.room_id AND e.mls_epoch=j.base_epoch AND e.kind='commit'
                   AND e.created_at_ms<=?3 AND j.expires_at_ms>?3
                   AND e.expires_at_ms=j.expires_at_ms AND length(e.ciphertext) BETWEEN 1 AND ?5
                   AND octet_length(e.sender_peer_id) BETWEEN 1 AND ?6
                 ORDER BY j.base_epoch LIMIT ?4",
        )
        .map_err(database_error)?;
    let mut rows = statement
        .query(params![
            wire_id.as_bytes(),
            base,
            now,
            SYNC_WINDOW,
            MAX_GROUP_MLS_OBJECT_BYTES as i64,
            MAX_SIGNER_TEXT_BYTES as i64,
        ])
        .map_err(database_error)?;
    let mut first = None;
    let mut expected = base_epoch;
    let mut bound = None;
    while let Some(row) = rows.next().map_err(database_error)? {
        let expires_at_ms = unsigned(row.get(6).map_err(database_error)?)?;
        if current_time()? >= expires_at_ms {
            return Ok(None);
        }
        let epoch = unsigned(row.get(1).map_err(database_error)?)?;
        let bindings = MlsEpochBindings {
            base: read_binding(row, 2)?,
            next: read_binding(row, 3)?,
        };
        if epoch != expected || bound.is_some_and(|prev| prev != bindings.base) {
            return Ok(None);
        }
        let mut local_id = [0; Id128::LENGTH];
        hex::decode_to_slice(
            row.get::<_, String>(0).map_err(database_error)?,
            &mut local_id,
        )
        .map_err(|_| AslError::InvalidDatabase)?;
        let signer = bs58::decode(row.get::<_, String>(4).map_err(database_error)?)
            .into_vec()
            .map_err(|_| AslError::InvalidDatabase)?;
        let step = MlsSyncStoredStep {
            local_id: GroupId(Id128(local_id)),
            base_epoch: epoch,
            expires_at_ms,
            bindings,
            signer: PeerId::from_bytes(signer).map_err(|_| AslError::InvalidDatabase)?,
            commit: row.get(5).map_err(database_error)?,
            version: RoomVersion {
                revision: unsigned(row.get(7).map_err(database_error)?)?,
                mls_epoch: unsigned(row.get(8).map_err(database_error)?)?,
                membership_epoch: unsigned(row.get(9).map_err(database_error)?)?,
                policy_revision: unsigned(row.get(10).map_err(database_error)?)?,
            },
        };
        if !verify(&step)? {
            return Ok(None);
        }
        expected += 1;
        bound = Some(bindings.next);
        if first.is_none() {
            first = Some(step);
        }
    }
    Ok(first.filter(|step| {
        expected == step.version.mls_epoch && head_binding.is_none_or(|head| Some(head) == bound)
    }))
}

fn read_binding(row: &rusqlite::Row<'_>, index: usize) -> Result<Hash32, AslError> {
    let bytes: Vec<u8> = row.get(index).map_err(database_error)?;
    Ok(Hash32(
        bytes.try_into().map_err(|_| AslError::InvalidDatabase)?,
    ))
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
