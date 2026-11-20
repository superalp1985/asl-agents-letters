//! Persistent incoming downloads and crash recovery.
//!
//! The database is the visibility gate. A chunk is only durable after its
//! exact range and hash have been checked, the bytes have been synced, and
//! the SQLite state has been advanced in the same logical operation.

use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use crate::evidence::{TrustDimension, TrustOutcome};
use asl_policy::{AuthorizedWriteFile, FileIdentity, WriteGrant, snapshot_files::DownloadOwner};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    manifest::{CHUNK_SIZE, Manifest, decode_manifest},
    task::{TaskId, TransferId},
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{Store, current_time_ms, database_error, open_store};

mod consent;
use consent::{Admission, ConsentBinding, StartIntent};
pub use consent::{DownloadConsent, DownloadMode, DownloadStart};

pub const DOWNLOAD_IDLE_MS: i64 = 300_000;
pub const DOWNLOAD_COOLDOWN_MS: i64 = 86_400_000;

const DEFAULT_DOWNLOAD_QUOTA: i64 = 20 << 30;
const DEFAULT_TASK_DOWNLOAD_QUOTA: i64 = 1 << 30;
const DEFAULT_UNKNOWN_SOURCE_QUOTA: i64 = 512 << 20;
const IDLE_DOWNLOAD_SWEEP_LIMIT: i64 = 8;

#[derive(Clone, Debug)]
pub struct DownloadRequest {
    pub content_id: Hash32,
    pub manifest: Vec<u8>,
    pub write_grant_id: Id128,
    pub destination_relative: PathBuf,
    pub sources: Vec<PeerId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadInfo {
    pub transfer_id: TransferId,
    pub task_id: TaskId,
    pub content_id: Hash32,
    pub file_size: u64,
    pub chunk_count: u32,
    pub durable_bytes: u64,
    pub state: String,
    pub part_path: PathBuf,
    pub destination_path: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DownloadSchedule {
    pub manifest: Manifest,
    pub durable_indexes: Vec<u32>,
    pub sources: Vec<PeerId>,
    pub expires_at_ms: i64,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    pub resumed: usize,
    pub repaired_chunks: usize,
    pub completed: usize,
    pub released: usize,
    pub cooled: usize,
}

pub struct DownloadBroker {
    store: Store,
    home: PathBuf,
    _owner: DownloadOwner,
}

impl DownloadBroker {
    pub fn open(home: &Path) -> Result<Self, AslError> {
        let owner = DownloadOwner::acquire(home)?;
        let store = open_store(&home.join("state").join("asl.sqlite3"))?;
        let mut broker = Self {
            store,
            home: home.to_owned(),
            _owner: owner,
        };
        broker.recover_downloads(current_time_ms())?;
        Ok(broker)
    }

    /// Non-interactive caller: never creates or implicitly answers a prompt.
    pub fn begin_download(&mut self, request: &DownloadRequest) -> Result<DownloadInfo, AslError> {
        self.start(request, StartIntent::AutomaticOnly)?.started()
    }

    pub fn request_download(
        &mut self,
        request: &DownloadRequest,
    ) -> Result<DownloadStart, AslError> {
        self.start(request, StartIntent::MayPrompt)
    }

    pub fn begin_approved_download(
        &mut self,
        request: &DownloadRequest,
        approval: Id128,
    ) -> Result<DownloadInfo, AslError> {
        self.start(request, StartIntent::UseApproval(approval))?
            .started()
    }

    fn start(
        &mut self,
        request: &DownloadRequest,
        intent: StartIntent,
    ) -> Result<DownloadStart, AslError> {
        let manifest = decode_manifest(&request.manifest, request.content_id.0)
            .map_err(|_| AslError::InvalidMessage)?;
        let filename = WriteGrant::filename(&request.destination_relative)?;
        let part_relative = append_suffix(Path::new(&filename), ".part")?;
        WriteGrant::filename(&part_relative)?;
        let bytes = i64::try_from(manifest.file_size).map_err(|_| AslError::QuotaExceeded)?;
        let content = hex::encode(request.content_id.0);
        let grant = hex::encode(request.write_grant_id.0);
        let sources = consent::source_set(&request.sources)?;
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        let (root, max_bytes, volume, file_id, epoch) = tx
            .query_row(
                "SELECT root_path,max_bytes,root_volume,root_file_id,epoch FROM write_grants
                 WHERE write_grant_id=?1 AND kind='inbox' AND status='active'",
                [&grant],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::PolicyDenied)?;
        let expected_root = file_identity(volume.as_deref(), file_id.as_deref())?;
        let retry_after: Option<i64> = tx
            .query_row(
                "SELECT retry_after_ms FROM transfer_cooldowns WHERE content_id=?1",
                [&content],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        if retry_after.is_some_and(|value| value > now) {
            return Err(AslError::PolicyDenied);
        }
        if retry_after.is_some() {
            tx.execute(
                "DELETE FROM transfer_cooldowns WHERE content_id=?1",
                [&content],
            )
            .map_err(database_error)?;
        }

        check_download_limits(&tx, bytes, has_stranger_source(&tx, &sources)?)?;
        check_write_grant_quota(&tx, &grant, bytes, max_bytes)?;

        let binding = ConsentBinding::new(&grant, epoch, &content, &filename, bytes, &sources)?;
        let (transfer_id, approval_deadline) = match binding.admit(&tx, intent, now)? {
            Admission::Pending(id) => {
                tx.commit().map_err(database_error)?;
                return Ok(DownloadStart::Pending(id));
            }
            Admission::Ready { transfer, deadline } => (transfer, deadline),
        };
        let task_id = TaskId(random_id());
        let reservation_id = random_id();
        let transfer = hex::encode(transfer_id.0.0);
        let task = hex::encode(task_id.0.0);
        let reservation = hex::encode(reservation_id.0);
        let expires = now.saturating_add(DOWNLOAD_IDLE_MS);
        tx.execute(
            "INSERT INTO tasks(task_id,direction,audience_json,state,created_at_ms,expires_at_ms)
             VALUES (?1,'incoming','{\"kind\":\"private\"}','transferring',?2,?3)",
            params![task, now, expires],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO reservations(reservation_id,task_id,peer_id,kind,bytes,state,progress_at_ms,expires_at_ms)
             VALUES (?1,?2,?3,'download',?4,'held',?5,?6)",
            params![reservation, task, sources.first(), bytes, now, expires],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO transfers(transfer_id,task_id,content_id,write_grant_id,reservation_id,
             part_relative,state,durable_bytes,created_at_ms,updated_at_ms,expires_at_ms,
             part_file_id,manifest_bytes)
             VALUES (?1,?2,?3,?4,?5,?6,'pending',0,?7,?7,?8,NULL,?9)",
            params![
                transfer,
                task,
                content,
                grant,
                reservation,
                path_text(&part_relative)?,
                now,
                expires,
                request.manifest.as_slice()
            ],
        )
        .map_err(database_error)?;
        for index in 0..manifest.chunk_hashes.len() {
            tx.execute(
                "INSERT INTO transfer_chunks(transfer_id,chunk_index,state)
                 VALUES (?1,?2,'missing')",
                params![
                    transfer,
                    i64::try_from(index).map_err(|_| AslError::InvalidMessage)?
                ],
            )
            .map_err(database_error)?;
        }
        for peer in sources {
            tx.execute(
                "INSERT INTO transfer_sources(transfer_id,peer_id,state)
                 VALUES (?1,?2,'candidate')",
                params![transfer, peer],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)?;

        let materialized = (|| {
            let check_materialization = |tx: &Transaction<'_>| {
                ensure_active_write_grant(tx, &grant, &root, &expected_root, epoch)?;
                let still_held: bool = tx.query_row(
                    "SELECT state='held' AND expires_at_ms>?2 FROM reservations WHERE reservation_id=?1",
                    params![reservation, current_time_ms()], |row| row.get(0)
                ).map_err(database_error)?;
                if !still_held || !consent::may_materialize(tx, approval_deadline)? {
                    return Err(AslError::PolicyDenied);
                }
                Ok(())
            };
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(database_error)?;
            check_materialization(&tx)?;
            let write_grant = restore_write_grant(Path::new(&root), &self.home, &expected_root)?;
            let mut part = write_grant.create_new(&part_relative)?;
            part.set_len(manifest.file_size)?;
            let identity = part.identity()?;
            let saved = tx
                .execute(
                    "UPDATE transfers SET part_file_id=?2
                     WHERE transfer_id=?1 AND state='pending' AND part_file_id IS NULL",
                    params![transfer, hex::encode(identity.file_id)],
                )
                .map_err(database_error)?;
            if saved != 1 {
                return Err(AslError::InvalidDatabase);
            }
            tx.commit().map_err(database_error)?;
            // Journal the exact file before releasing the writer; an
            // interruption during the flush can only clean up that file.
            part.retain();
            let initialized = (|| {
                part.sync_all()?;
                let tx = self
                    .store
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(database_error)?;
                check_materialization(&tx)?;
                tx.commit().map_err(database_error)
            })();
            if let Err(error) = initialized {
                part.remove()?;
                return Err(error);
            }
            Ok(())
        })();
        if let Err(error) = materialized {
            self.fail_without_cooldown(&transfer, now)?;
            return Err(error);
        }
        self.info(&transfer_id).map(DownloadStart::Started)
    }

    pub fn assign_chunk(
        &mut self,
        transfer_id: TransferId,
        peer_id: &PeerId,
        index: u32,
    ) -> Result<(), AslError> {
        let transfer = id_text(transfer_id.0.0);
        let peer = peer_text(peer_id);
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        let changed = tx
            .execute(
                "UPDATE transfer_chunks SET state='assigned',source_peer=?3
                 WHERE transfer_id=?1 AND chunk_index=?2 AND state='missing'
                 AND EXISTS(SELECT 1 FROM transfer_sources
                            WHERE transfer_id=?1 AND peer_id=?3
                            AND state IN ('candidate','active'))
                 AND EXISTS(
                     SELECT 1 FROM transfers t JOIN reservations r USING(reservation_id)
                     JOIN write_grants w ON w.write_grant_id=t.write_grant_id
                     WHERE t.transfer_id=?1 AND t.part_file_id IS NOT NULL AND t.expires_at_ms>?4
                       AND t.state IN ('pending','running','paused') AND r.state='held'
                       AND w.status='active' AND w.kind='inbox'
                 )",
                params![transfer, i64::from(index), peer, now],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::NotFound);
        }
        tx.execute(
            "UPDATE transfer_sources SET state='active'
             WHERE transfer_id=?1 AND peer_id=?2",
            params![transfer, peer],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE transfers SET state='running',updated_at_ms=?2
             WHERE transfer_id=?1 AND state IN ('pending','running','paused')",
            params![transfer, now],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }

    /// Returns an unfulfilled assignment to the missing set without crediting progress.
    pub fn unassign_chunk(
        &mut self,
        transfer_id: &TransferId,
        peer_id: &PeerId,
        index: u32,
    ) -> Result<bool, AslError> {
        let changed = self
            .store
            .connection
            .execute(
                "UPDATE transfer_chunks SET state='missing',source_peer=NULL
                 WHERE transfer_id=?1 AND source_peer=?2 AND chunk_index=?3 AND state='assigned'",
                params![id_text(transfer_id.0.0), peer_text(peer_id), index],
            )
            .map_err(database_error)?;
        Ok(changed == 1)
    }

    /// Reclaims work abandoned by the previous coordinator for this transfer.
    /// Only the Core process that owns download scheduling may call this.
    pub fn reset_chunk_assignments(&mut self, transfer_id: &TransferId) -> Result<(), AslError> {
        reset_assignments(&self.store.connection, &id_text(transfer_id.0.0))?;
        Ok(())
    }

    /// Reflects durable source penalties, including those from before a restart.
    pub fn chunk_source_available(
        &self,
        transfer_id: &TransferId,
        peer_id: &PeerId,
    ) -> Result<bool, AslError> {
        self.store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM transfer_sources
                 WHERE transfer_id=?1 AND peer_id=?2 AND state IN ('candidate','active'))",
                params![id_text(transfer_id.0.0), peer_text(peer_id)],
                |row| row.get(0),
            )
            .map_err(database_error)
    }

    pub fn write_chunk(
        &mut self,
        transfer_id: TransferId,
        peer_id: &PeerId,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), AslError> {
        let row = self.load_row(&transfer_id)?;
        let manifest = self.read_manifest(&row)?;
        let chunk = chunk(&manifest, index)?;
        let mut file = self.open_part(&row)?;
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, &row)?;
        if row.expires_at_ms <= current_time_ms() {
            return Err(AslError::ExpiredMessage);
        }
        let peer = peer_text(peer_id);
        let assigned: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM transfer_chunks
                    WHERE transfer_id=?1 AND chunk_index=?2
                      AND state='assigned' AND source_peer=?3
                )",
                params![row.transfer, i64::from(index), peer],
                |value| value.get(0),
            )
            .map_err(database_error)?;
        if !assigned {
            return Err(AslError::NotFound);
        }
        if bytes.len() != chunk.len || *blake3::hash(bytes).as_bytes() != chunk.hash {
            tx.execute(
                "UPDATE transfer_sources SET bad_hashes=bad_hashes+1,
                 state=CASE WHEN bad_hashes+1 >= 3 THEN 'banned' ELSE state END
                 WHERE transfer_id=?1 AND peer_id=?2",
                params![row.transfer, peer],
            )
            .map_err(database_error)?;
            tx.execute(
                "UPDATE transfer_chunks SET state='missing',source_peer=NULL,verified_at_ms=NULL
                 WHERE transfer_id=?1 AND source_peer=?2 AND state='assigned'",
                params![row.transfer, peer],
            )
            .map_err(database_error)?;
            tx.commit().map_err(database_error)?;
            self.record_integrity_observation(&row, peer_id, TrustOutcome::Negative)?;
            return Err(AslError::InvalidMessage);
        }
        file.seek(SeekFrom::Start(chunk.offset))?;
        file.write_all(bytes)?;
        // Flush without holding the shared SQLite writer. An interrupted or
        // revoked transfer still has only an assigned block, never a durable one.
        tx.commit().map_err(database_error)?;
        file.sync_all()?;
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, &row)?;
        if row.expires_at_ms <= current_time_ms() {
            return Err(AslError::ExpiredMessage);
        }
        let changed = tx
            .execute(
                "UPDATE transfer_chunks SET state='durable',verified_at_ms=?4
                 WHERE transfer_id=?1 AND chunk_index=?2 AND state='assigned' AND source_peer=?3",
                params![row.transfer, i64::from(index), peer, current_time_ms()],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::NotFound);
        }
        let now = current_time_ms();
        tx.execute(
            "UPDATE transfers SET durable_bytes=durable_bytes+?2,state='running',
             updated_at_ms=?3,expires_at_ms=?4 WHERE transfer_id=?1",
            params![
                row.transfer,
                i64::try_from(chunk.len).map_err(|_| AslError::InvalidMessage)?,
                now,
                now + DOWNLOAD_IDLE_MS
            ],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE reservations SET progress_at_ms=?2,expires_at_ms=?3
             WHERE reservation_id=?1 AND state='held'",
            params![row.reservation, now, now + DOWNLOAD_IDLE_MS],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE tasks SET state='transferring',expires_at_ms=?2 WHERE task_id=?1",
            params![row.task, now + DOWNLOAD_IDLE_MS],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        self.record_integrity_observation(&row, peer_id, TrustOutcome::Positive)
    }

    pub fn complete(&mut self, transfer_id: TransferId) -> Result<DownloadInfo, AslError> {
        let row = self.load_row(&transfer_id)?;
        let manifest = self.read_manifest(&row)?;
        let durable: i64 = self
            .store
            .connection
            .query_row(
                "SELECT count(*) FROM transfer_chunks
                 WHERE transfer_id=?1 AND state='durable'",
                [&row.transfer],
                |r| r.get(0),
            )
            .map_err(database_error)?;
        if durable != i64::try_from(manifest.chunk_hashes.len()).unwrap_or(i64::MAX) {
            return Err(AslError::InvalidPolicyState);
        }
        let mut part = self.open_part(&row)?;
        if !verify_file(&mut part, &manifest)? {
            self.fail_with_cooldown(&row, current_time_ms(), &mut part)?;
            return Err(AslError::InvalidMessage);
        }
        drop(part);
        self.finalize_files(&row, &manifest)?;
        self.info(&transfer_id)
    }

    pub fn release(&mut self, transfer_id: TransferId) -> Result<(), AslError> {
        let row = self.load_row(&transfer_id)?;
        let mut part = if row.grant_status == "active" && row.part_file_id.is_some() {
            self.open_part(&row).ok()
        } else {
            None
        };
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Some(part) = part.as_mut()
            && row.reservation_state == "held"
        {
            ensure_active_transfer(&tx, &row)?;
            part.remove()?;
        }
        release_row(&tx, &row, "cancelled", current_time_ms())?;
        tx.commit().map_err(database_error)
    }

    pub fn recover_downloads(&mut self, now_ms: i64) -> Result<RecoveryReport, AslError> {
        let ids: Vec<TransferId> = {
            let mut statement = self
                .store
                .connection
                .prepare(
                    "SELECT transfer_id FROM transfers
                     WHERE state IN ('pending','running','paused','verifying')
                     ORDER BY created_at_ms,transfer_id",
                )
                .map_err(database_error)?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(database_error)?
                .map(|value| {
                    value
                        .map_err(database_error)
                        .and_then(|text| parse_transfer(&text))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut report = RecoveryReport::default();
        for id in ids {
            match self.recover_one(id, now_ms)? {
                RecoveryAction::Resumed => report.resumed += 1,
                RecoveryAction::Repaired => report.repaired_chunks += 1,
                RecoveryAction::Completed => report.completed += 1,
                RecoveryAction::Released => report.released += 1,
                RecoveryAction::Cooled => report.cooled += 1,
                RecoveryAction::None => {}
            }
        }
        Ok(report)
    }

    pub fn info(&self, transfer_id: &TransferId) -> Result<DownloadInfo, AslError> {
        let row = self.load_row(transfer_id)?;
        let manifest = self.read_manifest(&row)?;
        let root = PathBuf::from(row.root);
        Ok(DownloadInfo {
            transfer_id: transfer_id.clone(),
            task_id: parse_task(&row.task)?,
            content_id: Hash32(parse_hash(&row.content)?),
            file_size: manifest.file_size,
            chunk_count: u32::try_from(manifest.chunk_hashes.len())
                .map_err(|_| AslError::InvalidDatabase)?,
            durable_bytes: u64::try_from(row.durable_bytes)
                .map_err(|_| AslError::InvalidDatabase)?,
            state: row.state,
            part_path: safe_join(&root, Path::new(&row.part))?,
            destination_path: safe_join(
                &root,
                Path::new(
                    row.part
                        .strip_suffix(".part")
                        .ok_or(AslError::InvalidDatabase)?,
                ),
            )?,
        })
    }

    /// Loads scheduling state before assigning any new blocks, after recovery has
    /// rechecked the durable data and reset the old process's assignments.
    pub fn schedule(&self, transfer_id: &TransferId) -> Result<DownloadSchedule, AslError> {
        let tx = self
            .store
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let row = load_row_tx(&tx, &id_text(transfer_id.0.0))?;
        ensure_active_transfer(&tx, &row)?;
        if row.expires_at_ms <= current_time_ms() || row.part_file_id.is_none() {
            return Err(AslError::PolicyDenied);
        }
        let manifest = self.read_manifest(&row)?;
        let durable_indexes = durable_indexes(&tx, &row.transfer)?;
        let sources = {
            let mut statement = tx
                .prepare(
                    "SELECT peer_id FROM transfer_sources WHERE transfer_id=?1
                     AND state IN ('candidate','active') ORDER BY peer_id",
                )
                .map_err(database_error)?;
            statement
                .query_map([&row.transfer], |value| value.get::<_, String>(0))
                .map_err(database_error)?
                .map(|value| parse_peer(&value.map_err(database_error)?))
                .collect::<Result<Vec<_>, _>>()?
        };
        tx.commit().map_err(database_error)?;
        Ok(DownloadSchedule {
            manifest,
            durable_indexes,
            sources,
            expires_at_ms: row.expires_at_ms,
        })
    }

    pub fn source_is_registered(
        &self,
        agent: asl_types::ids::AgentId,
        peer: &PeerId,
    ) -> Result<bool, AslError> {
        self.store.has_registered_transfer_peer(agent, peer)
    }

    /// Recheck the persisted progress deadline before releasing an idle task.
    /// Returns its current deadline if a durable write already extended it.
    pub fn expire_idle_download(
        &mut self,
        transfer_id: &TransferId,
        now_ms: i64,
    ) -> Result<Option<i64>, AslError> {
        let row = self.load_row(transfer_id)?;
        if row.reservation_state != "held" {
            return Ok(None);
        }
        if row.expires_at_ms > now_ms {
            return Ok(Some(row.expires_at_ms));
        }
        self.release_inactive(&row, now_ms)?;
        Ok(None)
    }

    /// Reclaim a bounded batch, including paused or queued work with no live
    /// scheduler. A held reservation is the ownership gate.
    pub fn sweep_idle_downloads(&mut self, now_ms: i64) -> Result<(), AslError> {
        let ids = {
            let mut statement = self
                .store
                .connection
                .prepare(
                    "SELECT t.transfer_id FROM transfers t JOIN reservations r USING(reservation_id)
                     WHERE r.state='held' AND t.expires_at_ms<=?1
                     ORDER BY t.expires_at_ms,t.transfer_id LIMIT ?2",
                )
                .map_err(database_error)?;
            statement
                .query_map(params![now_ms, IDLE_DOWNLOAD_SWEEP_LIMIT], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(database_error)?
                .map(|row| parse_transfer(&row.map_err(database_error)?))
                .collect::<Result<Vec<_>, _>>()?
        };
        for id in ids {
            self.expire_idle_download(&id, now_ms)?;
        }
        Ok(())
    }

    fn release_inactive(&mut self, row: &TransferRow, now_ms: i64) -> Result<(), AslError> {
        let mut part = if row.reservation_state == "held" && row.grant_status == "active" {
            self.open_part(row).ok()
        } else {
            None
        };
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Some(part) = part.as_mut() {
            ensure_active_transfer(&tx, row)?;
            part.remove()?;
        }
        reset_assignments(&tx, &row.transfer)?;
        release_row(&tx, row, "paused", now_ms)?;
        tx.commit().map_err(database_error)
    }

    fn recover_one(
        &mut self,
        transfer_id: TransferId,
        now_ms: i64,
    ) -> Result<RecoveryAction, AslError> {
        let row = self.load_row(&transfer_id)?;
        if row.reservation_state != "held"
            || row.expires_at_ms <= now_ms
            || row.grant_status != "active"
        {
            self.release_inactive(&row, now_ms)?;
            return Ok(RecoveryAction::Released);
        }
        if row.part_file_id.is_none() || row.manifest_bytes.is_none() {
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(database_error)?;
            release_row(&tx, &row, "paused", now_ms)?;
            tx.commit().map_err(database_error)?;
            return Ok(RecoveryAction::Released);
        }

        let manifest = match self.read_manifest(&row) {
            Ok(value) => value,
            Err(_) => {
                let mut part = self.open_part(&row).ok();
                let tx = self
                    .store
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(database_error)?;
                if let Some(part) = part.as_mut() {
                    ensure_active_transfer(&tx, &row)?;
                    part.remove()?;
                }
                release_row(&tx, &row, "failed", now_ms)?;
                tx.commit().map_err(database_error)?;
                return Ok(RecoveryAction::Released);
            }
        };
        let reset = reset_assignments(&self.store.connection, &row.transfer)?;
        let grant = match self.write_grant(&row) {
            Ok(grant) => grant,
            Err(_) => {
                let tx = self
                    .store
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(database_error)?;
                release_row(&tx, &row, "paused", now_ms)?;
                tx.commit().map_err(database_error)?;
                return Ok(RecoveryAction::Released);
            }
        };
        let identity = part_identity(&row)?;
        let final_relative = destination_relative(&row)?;
        let (mut candidate, is_part) = match grant.open_existing(Path::new(&row.part), &identity) {
            Ok(file) => (file, true),
            Err(_) => match grant.open_existing(&final_relative, &identity) {
                Ok(file) => (file, false),
                Err(_) => {
                    let tx = self
                        .store
                        .connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(database_error)?;
                    release_row(&tx, &row, "failed", now_ms)?;
                    tx.commit().map_err(database_error)?;
                    return Ok(RecoveryAction::Released);
                }
            },
        };
        if candidate.len()? != manifest.file_size {
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(database_error)?;
            ensure_active_transfer(&tx, &row)?;
            candidate.remove()?;
            release_row(&tx, &row, "failed", now_ms)?;
            tx.commit().map_err(database_error)?;
            return Ok(RecoveryAction::Released);
        }
        let repaired =
            verify_durable_chunks(&self.store.connection, &row, &mut candidate, &manifest)?;
        let durable = durable_bytes(&self.store.connection, &row.transfer, &manifest)?;
        self.store
            .connection
            .execute(
                "UPDATE transfers SET durable_bytes=?2,state='running',updated_at_ms=?3
                 WHERE transfer_id=?1",
                params![row.transfer, durable, now_ms],
            )
            .map_err(database_error)?;
        if durable == i64::try_from(manifest.file_size).map_err(|_| AslError::InvalidDatabase)? {
            if verify_file(&mut candidate, &manifest)? {
                drop(candidate);
                self.finalize_files(&row, &manifest)?;
                return Ok(RecoveryAction::Completed);
            }
            self.fail_with_cooldown(&row, now_ms, &mut candidate)?;
            return Ok(RecoveryAction::Cooled);
        }
        if !is_part {
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(database_error)?;
            ensure_active_transfer(&tx, &row)?;
            grant.rename_new(&mut candidate, Path::new(&row.part))?;
            tx.commit().map_err(database_error)?;
        }
        if repaired > 0 {
            Ok(RecoveryAction::Repaired)
        } else if reset > 0 {
            Ok(RecoveryAction::Resumed)
        } else {
            Ok(RecoveryAction::None)
        }
    }

    fn finalize_files(&mut self, row: &TransferRow, manifest: &Manifest) -> Result<(), AslError> {
        let grant = self.write_grant(row)?;
        let final_relative = destination_relative(row)?;
        let identity = part_identity(row)?;
        let (mut output, is_part) = match grant.open_existing(Path::new(&row.part), &identity) {
            Ok(file) => (file, true),
            Err(_) => (grant.open_existing(&final_relative, &identity)?, false),
        };
        if !verify_file(&mut output, manifest)? {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, row)?;
        if is_part {
            grant.rename_new(&mut output, &final_relative)?;
        }
        // Keep rename, its flush, and authorization serialized. The Core's
        // interactive authority gate treats SQLite contention as a retryable
        // conflict rather than stopping the network loop.
        output.sync_all()?;
        let now = current_time_ms();
        tx.execute(
            "UPDATE transfers SET state='complete',durable_bytes=?2,updated_at_ms=?3,expires_at_ms=?3
             WHERE transfer_id=?1",
            params![row.transfer, i64::try_from(manifest.file_size).map_err(|_| AslError::InvalidMessage)?, now],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE reservations SET state='consumed',progress_at_ms=?2,expires_at_ms=?2
             WHERE reservation_id=?1 AND state='held'",
            params![row.reservation, now],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE tasks SET state='done',expires_at_ms=?2 WHERE task_id=?1",
            params![row.task, now],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(())
    }

    fn fail_with_cooldown(
        &mut self,
        row: &TransferRow,
        now: i64,
        file: &mut AuthorizedWriteFile,
    ) -> Result<(), AslError> {
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, row)?;
        tx.execute(
            "INSERT INTO transfer_cooldowns(content_id,retry_after_ms,reason)
             VALUES (?1,?2,'full_hash_mismatch')
             ON CONFLICT(content_id) DO UPDATE SET
             retry_after_ms=excluded.retry_after_ms,reason=excluded.reason",
            params![row.content, now.saturating_add(DOWNLOAD_COOLDOWN_MS)],
        )
        .map_err(database_error)?;
        file.remove()?;
        release_row(&tx, row, "failed", now)?;
        tx.commit().map_err(database_error)?;
        Ok(())
    }

    fn fail_without_cooldown(&mut self, transfer: &str, now: i64) -> Result<(), AslError> {
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let row = load_row_tx(&tx, transfer)?;
        release_row(&tx, &row, "failed", now)?;
        tx.commit().map_err(database_error)
    }

    fn record_integrity_observation(
        &mut self,
        row: &TransferRow,
        peer: &PeerId,
        outcome: TrustOutcome,
    ) -> Result<(), AslError> {
        let mut evidence = Vec::with_capacity(row.transfer.len() + peer.as_bytes().len() + 32);
        evidence.extend_from_slice(b"ASL-TRANSFER-INTEGRITY-v1\0");
        evidence.extend_from_slice(row.transfer.as_bytes());
        evidence.extend_from_slice(peer.as_bytes());
        self.store.record_peer_trust_observation(
            peer,
            TrustDimension::Integrity,
            outcome,
            Hash32(*blake3::hash(&evidence).as_bytes()),
            u64::try_from(current_time_ms()).map_err(|_| AslError::InvalidDatabase)?,
        )?;
        Ok(())
    }

    fn load_row(&self, transfer_id: &TransferId) -> Result<TransferRow, AslError> {
        let transfer = id_text(transfer_id.0.0);
        self.store
            .connection
            .query_row(
                "SELECT t.transfer_id,t.task_id,t.content_id,t.write_grant_id,t.reservation_id,
                 t.part_relative,t.state,t.durable_bytes,t.expires_at_ms,
                 r.state,w.root_path,w.status,w.root_volume,w.root_file_id,
                 t.part_file_id,t.manifest_bytes,w.kind
                 FROM transfers t JOIN reservations r USING(reservation_id)
                 JOIN write_grants w ON w.write_grant_id=t.write_grant_id
                 WHERE t.transfer_id=?1",
                [&transfer],
                read_row,
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::NotFound)
    }

    fn read_manifest(&self, row: &TransferRow) -> Result<Manifest, AslError> {
        let bytes = row
            .manifest_bytes
            .as_deref()
            .ok_or(AslError::InvalidDatabase)?;
        decode_manifest(bytes, parse_hash(&row.content)?).map_err(|_| AslError::InvalidDatabase)
    }

    fn write_grant(&self, row: &TransferRow) -> Result<WriteGrant, AslError> {
        if row.grant_status != "active" || row.grant_kind != "inbox" {
            return Err(AslError::PolicyDenied);
        }
        let expected = file_identity(row.root_volume.as_deref(), row.root_file_id.as_deref())?;
        restore_write_grant(Path::new(&row.root), &self.home, &expected)
    }

    fn open_part(&self, row: &TransferRow) -> Result<AuthorizedWriteFile, AslError> {
        self.write_grant(row)?
            .open_existing(Path::new(&row.part), &part_identity(row)?)
    }
}

#[derive(Clone, Debug)]
struct TransferRow {
    transfer: String,
    task: String,
    content: String,
    reservation: String,
    root: String,
    root_volume: Option<String>,
    root_file_id: Option<String>,
    part: String,
    part_file_id: Option<String>,
    manifest_bytes: Option<Vec<u8>>,
    grant_kind: String,
    state: String,
    durable_bytes: i64,
    expires_at_ms: i64,
    reservation_state: String,
    grant_status: String,
}

#[derive(Clone, Copy)]
enum RecoveryAction {
    None,
    Resumed,
    Repaired,
    Completed,
    Released,
    Cooled,
}

struct ChunkRange {
    offset: u64,
    len: usize,
    hash: [u8; 32],
}

fn chunk(manifest: &Manifest, index: u32) -> Result<ChunkRange, AslError> {
    let index = usize::try_from(index).map_err(|_| AslError::NotFound)?;
    let hash = *manifest.chunk_hashes.get(index).ok_or(AslError::NotFound)?;
    let offset = u64::from(index as u32)
        .checked_mul(u64::from(CHUNK_SIZE))
        .ok_or(AslError::InvalidMessage)?;
    let len = manifest
        .file_size
        .checked_sub(offset)
        .ok_or(AslError::NotFound)?
        .min(u64::from(CHUNK_SIZE));
    Ok(ChunkRange {
        offset,
        len: usize::try_from(len).map_err(|_| AslError::InvalidMessage)?,
        hash,
    })
}

fn has_stranger_source(tx: &Transaction<'_>, sources: &[String]) -> Result<bool, AslError> {
    let mut stranger = sources.is_empty();
    let mut lookup = tx
        .prepare(
            "SELECT c.agent_id IS NOT NULL FROM peers p
             LEFT JOIN authorized_contacts c USING(agent_id)
             WHERE p.peer_id=?1",
        )
        .map_err(database_error)?;
    for peer in sources {
        let contact: bool = lookup
            .query_row([peer], |row| row.get(0))
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::NotFound)?;
        stranger |= !contact;
    }
    Ok(stranger)
}

fn check_download_limits(
    tx: &Transaction<'_>,
    requested: i64,
    stranger_source: bool,
) -> Result<(), AslError> {
    let global = setting(tx, "storage.download_quota_bytes", DEFAULT_DOWNLOAD_QUOTA)?;
    let task = setting(
        tx,
        "storage.task_download_quota_bytes",
        DEFAULT_TASK_DOWNLOAD_QUOTA,
    )?;
    let unknown = setting(
        tx,
        "storage.unknown_source_reservation_bytes",
        DEFAULT_UNKNOWN_SOURCE_QUOTA,
    )?;
    let used: i64 = tx
        .query_row(
            "SELECT coalesce(sum(bytes),0) FROM reservations
             WHERE kind='download' AND state IN ('held','consumed')",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !fits(used, requested, global) || requested > task {
        return Err(AslError::QuotaExceeded);
    }
    if stranger_source {
        let held: i64 = tx
            .query_row(
                "SELECT coalesce(sum(r.bytes),0) FROM reservations r
                 JOIN transfers t USING(reservation_id)
                 WHERE r.kind='download' AND r.state='held'
                   AND (r.peer_id IS NULL OR EXISTS(
                       SELECT 1 FROM transfer_sources s
                       JOIN peers p USING(peer_id)
                       LEFT JOIN authorized_contacts c USING(agent_id)
                       WHERE s.transfer_id=t.transfer_id AND c.agent_id IS NULL
                   ))",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !fits(held, requested, unknown) {
            return Err(AslError::QuotaExceeded);
        }
    }
    Ok(())
}

fn check_write_grant_quota(
    tx: &Transaction<'_>,
    grant_id: &str,
    requested: i64,
    limit: i64,
) -> Result<(), AslError> {
    let used: i64 = tx
        .query_row(
            "SELECT coalesce(sum(r.bytes),0)
             FROM reservations r JOIN transfers t USING(reservation_id)
             WHERE t.write_grant_id=?1 AND r.kind='download'
               AND r.state IN ('held','consumed')",
            [grant_id],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if fits(used, requested, limit) {
        Ok(())
    } else {
        Err(AslError::QuotaExceeded)
    }
}

fn setting(tx: &Transaction<'_>, key: &str, default: i64) -> Result<i64, AslError> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT value_json FROM settings WHERE key=?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    raw.map(|value| serde_json::from_str::<i64>(&value).map_err(|_| AslError::InvalidPolicyState))
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn fits(used: i64, requested: i64, limit: i64) -> bool {
    used.checked_add(requested)
        .is_some_and(|value| value <= limit)
}

fn ensure_active_transfer(tx: &Transaction<'_>, row: &TransferRow) -> Result<(), AslError> {
    let active: bool = tx
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM transfers t JOIN reservations r USING(reservation_id)
                JOIN write_grants w ON w.write_grant_id=t.write_grant_id
                WHERE t.transfer_id=?1 AND r.state='held'
                  AND t.state IN ('pending','running','paused','verifying')
                  AND w.status='active' AND w.kind='inbox'
            )",
            [&row.transfer],
            |value| value.get(0),
        )
        .map_err(database_error)?;
    if active {
        Ok(())
    } else {
        Err(AslError::PolicyDenied)
    }
}

fn ensure_active_write_grant(
    tx: &Transaction<'_>,
    grant_id: &str,
    root_path: &str,
    identity: &FileIdentity,
    epoch: i64,
) -> Result<(), AslError> {
    let active: bool = tx
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM write_grants
                WHERE write_grant_id=?1 AND kind='inbox' AND root_path=?2 AND status='active'
                  AND root_volume=?3 AND root_file_id=?4 AND epoch=?5
            )",
            params![
                grant_id,
                root_path,
                format!("{:016x}", identity.volume_serial),
                hex::encode(identity.file_id),
                epoch
            ],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if active {
        Ok(())
    } else {
        Err(AslError::PolicyDenied)
    }
}

fn reset_assignments(connection: &rusqlite::Connection, transfer: &str) -> Result<usize, AslError> {
    connection
        .execute(
            "UPDATE transfer_chunks SET state='missing',source_peer=NULL
             WHERE transfer_id=?1 AND state='assigned'",
            [transfer],
        )
        .map_err(database_error)
}

fn release_row(
    tx: &Transaction<'_>,
    row: &TransferRow,
    transfer_state: &str,
    now: i64,
) -> Result<(), AslError> {
    tx.execute(
        "UPDATE reservations SET state='released',progress_at_ms=?2,expires_at_ms=?2
         WHERE reservation_id=?1 AND state='held'",
        params![row.reservation, now],
    )
    .map_err(database_error)?;
    tx.execute(
        "UPDATE transfers SET state=?2,updated_at_ms=?3,expires_at_ms=?3
         WHERE transfer_id=?1 AND state NOT IN ('complete','cancelled')",
        params![row.transfer, transfer_state, now],
    )
    .map_err(database_error)?;
    tx.execute(
        "UPDATE tasks SET state=CASE WHEN ?2='cancelled' THEN 'cancelled' ELSE 'failed' END,
         expires_at_ms=?3 WHERE task_id=?1",
        params![row.task, transfer_state, now],
    )
    .map_err(database_error)?;
    Ok(())
}

fn load_row_tx(tx: &Transaction<'_>, transfer: &str) -> Result<TransferRow, AslError> {
    tx.query_row(
        "SELECT t.transfer_id,t.task_id,t.content_id,t.write_grant_id,t.reservation_id,
         t.part_relative,t.state,t.durable_bytes,t.expires_at_ms,
         r.state,w.root_path,w.status,w.root_volume,w.root_file_id,
         t.part_file_id,t.manifest_bytes,w.kind
         FROM transfers t JOIN reservations r USING(reservation_id)
         JOIN write_grants w ON w.write_grant_id=t.write_grant_id
         WHERE t.transfer_id=?1",
        [transfer],
        read_row,
    )
    .optional()
    .map_err(database_error)?
    .ok_or(AslError::NotFound)
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransferRow> {
    Ok(TransferRow {
        transfer: row.get(0)?,
        task: row.get(1)?,
        content: row.get(2)?,
        reservation: row.get(4)?,
        part: row.get(5)?,
        state: row.get(6)?,
        durable_bytes: row.get(7)?,
        expires_at_ms: row.get(8)?,
        reservation_state: row.get(9)?,
        root: row.get(10)?,
        grant_status: row.get(11)?,
        root_volume: row.get(12)?,
        root_file_id: row.get(13)?,
        part_file_id: row.get(14)?,
        manifest_bytes: row.get(15)?,
        grant_kind: row.get(16)?,
    })
}

fn durable_indexes(db: &rusqlite::Connection, transfer: &str) -> Result<Vec<u32>, AslError> {
    let mut statement = db
        .prepare(
            "SELECT chunk_index FROM transfer_chunks
             WHERE transfer_id=?1 AND state='durable' ORDER BY chunk_index",
        )
        .map_err(database_error)?;
    statement
        .query_map([transfer], |value| value.get::<_, u32>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn verify_durable_chunks(
    db: &rusqlite::Connection,
    row: &TransferRow,
    file: &mut AuthorizedWriteFile,
    manifest: &Manifest,
) -> Result<usize, AslError> {
    let mut repaired = 0;
    for index in durable_indexes(db, &row.transfer)? {
        let chunk = chunk(manifest, index)?;
        file.seek(SeekFrom::Start(chunk.offset))?;
        let mut bytes = vec![0; chunk.len];
        file.read_exact(&mut bytes)?;
        if *blake3::hash(&bytes).as_bytes() != chunk.hash {
            db.execute(
                "UPDATE transfer_chunks SET state='missing',source_peer=NULL,verified_at_ms=NULL
                 WHERE transfer_id=?1 AND chunk_index=?2",
                params![row.transfer, i64::from(index)],
            )
            .map_err(database_error)?;
            repaired += 1;
        }
    }
    Ok(repaired)
}

fn restore_write_grant(
    root: &Path,
    home: &Path,
    expected: &FileIdentity,
) -> Result<WriteGrant, AslError> {
    let protected = if root == home.join("derived") {
        home.join("state")
    } else {
        home.to_owned()
    };
    WriteGrant::restore(root, &protected, expected)
}

fn file_identity(volume: Option<&str>, file_id: Option<&str>) -> Result<FileIdentity, AslError> {
    let volume_serial = u64::from_str_radix(volume.ok_or(AslError::InvalidDatabase)?, 16)
        .map_err(|_| AslError::InvalidDatabase)?;
    let mut file_id_bytes = [0; 16];
    hex::decode_to_slice(
        file_id.ok_or(AslError::InvalidDatabase)?,
        &mut file_id_bytes,
    )
    .map_err(|_| AslError::InvalidDatabase)?;
    Ok(FileIdentity {
        volume_serial,
        file_id: file_id_bytes,
    })
}

fn part_identity(row: &TransferRow) -> Result<FileIdentity, AslError> {
    file_identity(row.root_volume.as_deref(), row.part_file_id.as_deref())
}

fn destination_relative(row: &TransferRow) -> Result<PathBuf, AslError> {
    let name = row
        .part
        .strip_suffix(".part")
        .ok_or(AslError::InvalidDatabase)?;
    normalize_filename(Path::new(name))
}

fn durable_bytes(
    db: &rusqlite::Connection,
    transfer: &str,
    manifest: &Manifest,
) -> Result<i64, AslError> {
    durable_indexes(db, transfer)?
        .into_iter()
        .try_fold(0_i64, |total, index| {
            let length = chunk(manifest, index)?.len;
            total
                .checked_add(i64::try_from(length).map_err(|_| AslError::InvalidMessage)?)
                .ok_or(AslError::InvalidDatabase)
        })
}

fn verify_file(file: &mut AuthorizedWriteFile, manifest: &Manifest) -> Result<bool, AslError> {
    if file.len()? != manifest.file_size {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes() == manifest.file_hash)
}

fn normalize_relative(path: &Path) -> Result<PathBuf, AslError> {
    if path.as_os_str().is_empty() {
        return Err(AslError::InvalidStorageRoot);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(AslError::InvalidStorageRoot);
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        Err(AslError::InvalidStorageRoot)
    } else {
        Ok(normalized)
    }
}

fn normalize_filename(path: &Path) -> Result<PathBuf, AslError> {
    let normalized = normalize_relative(path)?;
    if normalized.components().count() == 1 {
        Ok(normalized)
    } else {
        Err(AslError::InvalidStorageRoot)
    }
}

fn safe_join(root: &Path, relative: &Path) -> Result<PathBuf, AslError> {
    let relative = normalize_relative(relative)?;
    Ok(root.join(relative))
}

fn append_suffix(path: &Path, suffix: &str) -> Result<PathBuf, AslError> {
    let text = path.to_str().ok_or(AslError::InvalidStorageRoot)?;
    Ok(PathBuf::from(format!("{text}{suffix}")))
}

fn path_text(path: &Path) -> Result<String, AslError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(AslError::InvalidStorageRoot)
}

fn parse_hash(value: &str) -> Result<[u8; 32], AslError> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(bytes)
}

fn parse_transfer(value: &str) -> Result<TransferId, AslError> {
    Ok(TransferId(parse_id(value)?))
}

fn parse_task(value: &str) -> Result<TaskId, AslError> {
    Ok(TaskId(parse_id(value)?))
}

fn parse_id(value: &str) -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(Id128(bytes))
}

fn id_text(id: [u8; 16]) -> String {
    hex::encode(id)
}

fn peer_text(peer: &PeerId) -> String {
    bs58::encode(peer.as_bytes()).into_string()
}

fn parse_peer(value: &str) -> Result<PeerId, AslError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
}

fn random_id() -> Id128 {
    Id128(rand::random())
}
