//! Persistent incoming downloads and crash recovery.
//!
//! The database is the visibility gate. A chunk is only durable after its
//! exact range and hash have been checked, the bytes have been synced, and
//! the SQLite state has been advanced in the same logical operation.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use asl_policy::snapshot_files::PinnedHome;
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    manifest::{CHUNK_SIZE, Manifest, decode_manifest},
    task::{TaskId, TransferId},
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{Store, current_time_ms, database_error, open_store};

pub const DOWNLOAD_IDLE_MS: i64 = 300_000;
pub const DOWNLOAD_COOLDOWN_MS: i64 = 86_400_000;

const DEFAULT_DOWNLOAD_QUOTA: i64 = 20 << 30;
const DEFAULT_TASK_DOWNLOAD_QUOTA: i64 = 1 << 30;
const DEFAULT_UNKNOWN_SOURCE_QUOTA: i64 = 512 << 20;

#[derive(Clone, Debug)]
pub struct DownloadRequest {
    pub content_id: Hash32,
    pub manifest: Vec<u8>,
    pub write_grant_id: Id128,
    pub destination_relative: PathBuf,
    pub sources: Vec<PeerId>,
    pub now_ms: u64,
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
    pub manifest_path: PathBuf,
    pub destination_path: PathBuf,
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
    _pin: PinnedHome,
}

impl DownloadBroker {
    pub fn open(home: &Path) -> Result<Self, AslError> {
        fs::create_dir_all(home.join("state"))?;
        fs::create_dir_all(home.join("incoming"))?;
        let pin = PinnedHome::open(home)?;
        let store = open_store(&home.join("state").join("asl.sqlite3"))?;
        let mut broker = Self {
            store,
            home: home.to_owned(),
            _pin: pin,
        };
        broker.recover_downloads(current_time_ms())?;
        Ok(broker)
    }

    pub fn begin_download(&mut self, request: &DownloadRequest) -> Result<DownloadInfo, AslError> {
        let manifest = decode_manifest(&request.manifest, request.content_id.0)
            .map_err(|_| AslError::InvalidMessage)?;
        let destination = normalize_relative(&request.destination_relative)?;
        let now = i64_time(request.now_ms)?;
        let content = hex::encode(request.content_id.0);
        let grant = hex::encode(request.write_grant_id.0);
        let source = self.lookup_source(&request.sources)?;
        let (root, max_bytes) = self
            .store
            .connection
            .query_row(
                "SELECT root_path,max_bytes FROM write_grants
                 WHERE write_grant_id=?1 AND status='active'",
                [&grant],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::PolicyDenied)?;
        if max_bytes < i64::try_from(manifest.file_size).map_err(|_| AslError::QuotaExceeded)? {
            return Err(AslError::QuotaExceeded);
        }
        let root = PathBuf::from(root);
        let final_path = safe_join(&root, &destination)?;
        let part_relative = append_suffix(&destination, ".part")?;
        let part_path = safe_join(&root, &part_relative)?;
        if final_path.exists() || part_path.exists() {
            return Err(AslError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "download destination is already occupied",
            )));
        }

        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
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

        let bytes = i64::try_from(manifest.file_size).map_err(|_| AslError::QuotaExceeded)?;
        check_download_limits(&tx, bytes, source.is_none())?;

        let transfer_id = TransferId(random_id());
        let task_id = TaskId(random_id());
        let reservation_id = random_id();
        let transfer = hex::encode(transfer_id.0.0);
        let task = hex::encode(task_id.0.0);
        let reservation = hex::encode(reservation_id.0);
        let manifest_relative = format!("incoming/{transfer}.mnf");
        let expires = now.saturating_add(DOWNLOAD_IDLE_MS);
        tx.execute(
            "INSERT INTO tasks(task_id,direction,audience_json,state,created_at_ms,expires_at_ms)
             VALUES (?1,'outgoing','{\"kind\":\"private\"}','transferring',?2,?3)",
            params![task, now, expires],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO reservations(reservation_id,task_id,peer_id,kind,bytes,state,progress_at_ms,expires_at_ms)
             VALUES (?1,?2,?3,'download',?4,'held',?5,?6)",
            params![reservation, task, source, bytes, now, expires],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO transfers(transfer_id,task_id,content_id,write_grant_id,reservation_id,
             part_relative,manifest_relative,state,durable_bytes,created_at_ms,updated_at_ms,expires_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',0,?8,?8,?9)",
            params![
                transfer,
                task,
                content,
                grant,
                reservation,
                path_text(&part_relative)?,
                manifest_relative,
                now,
                expires
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
        for peer in &request.sources {
            let peer = peer_text(peer);
            let known: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM peers WHERE peer_id=?1)",
                    [&peer],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if !known {
                return Err(AslError::NotFound);
            }
            tx.execute(
                "INSERT INTO transfer_sources(transfer_id,peer_id,state)
                 VALUES (?1,?2,'candidate')",
                params![transfer, peer],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)?;

        let manifest_path = self.home.join(&manifest_relative);
        if let Err(error) = write_new_file(&manifest_path, &request.manifest, None) {
            self.fail_without_cooldown(&transfer, now)?;
            return Err(error);
        }
        if let Err(error) = prepare_part(&part_path, manifest.file_size) {
            let _ = fs::remove_file(&manifest_path);
            self.fail_without_cooldown(&transfer, now)?;
            return Err(error);
        }
        self.info(&transfer_id)
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
        let changed = tx
            .execute(
                "UPDATE transfer_chunks SET state='assigned',source_peer=?3
                 WHERE transfer_id=?1 AND chunk_index=?2 AND state='missing'
                 AND EXISTS(SELECT 1 FROM transfer_sources
                            WHERE transfer_id=?1 AND peer_id=?3
                            AND state IN ('candidate','active'))",
                params![transfer, i64::from(index), peer],
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
            params![transfer, current_time_ms()],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
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
        if bytes.len() != chunk.len || *blake3::hash(bytes).as_bytes() != chunk.hash {
            self.record_bad_hash(&row, peer_id)?;
            return Err(AslError::InvalidMessage);
        }
        let part_path = self.part_path(&row)?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&part_path)
            .map_err(AslError::from)?;
        file.seek(SeekFrom::Start(chunk.offset))?;
        file.write_all(bytes)?;
        file.sync_all()?;

        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, &row)?;
        let peer = peer_text(peer_id);
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
        tx.commit().map_err(database_error)
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
        let part = self.part_path(&row)?;
        if !verify_file(&part, &manifest)? {
            self.fail_with_cooldown(&row, current_time_ms())?;
            self.remove_staging(&row)?;
            return Err(AslError::InvalidMessage);
        }
        self.finalize_files(&row, &manifest)?;
        self.info(&transfer_id)
    }

    pub fn release(&mut self, transfer_id: TransferId) -> Result<(), AslError> {
        let row = self.load_row(&transfer_id)?;
        self.remove_staging(&row)?;
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
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
            manifest_path: self.home.join(&row.manifest),
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
            self.remove_staging(&row)?;
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
                self.remove_staging(&row)?;
                let tx = self
                    .store
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(database_error)?;
                release_row(&tx, &row, "failed", now_ms)?;
                tx.commit().map_err(database_error)?;
                return Ok(RecoveryAction::Released);
            }
        };
        let reset = self
            .store
            .connection
            .execute(
                "UPDATE transfer_chunks SET state='missing',source_peer=NULL
                 WHERE transfer_id=?1 AND state='assigned'",
                [&row.transfer],
            )
            .map_err(database_error)?;
        let part = self.part_path(&row)?;
        let final_path = self.final_path(&row)?;
        let candidate = if part.exists() {
            Some(part.clone())
        } else if final_path.exists() {
            Some(final_path.clone())
        } else {
            None
        };
        let Some(candidate) = candidate else {
            self.remove_staging(&row)?;
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(database_error)?;
            release_row(&tx, &row, "failed", now_ms)?;
            tx.commit().map_err(database_error)?;
            return Ok(RecoveryAction::Released);
        };
        if candidate.metadata()?.len() != manifest.file_size {
            self.remove_staging(&row)?;
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(database_error)?;
            release_row(&tx, &row, "failed", now_ms)?;
            tx.commit().map_err(database_error)?;
            return Ok(RecoveryAction::Released);
        }
        let repaired = verify_durable_chunks(&self.store.connection, &row, &candidate, &manifest)?;
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
            if verify_file(&candidate, &manifest)? {
                self.finalize_files(&row, &manifest)?;
                return Ok(RecoveryAction::Completed);
            }
            self.fail_with_cooldown(&row, now_ms)?;
            let _ = fs::remove_file(&part);
            let _ = fs::remove_file(self.home.join(&row.manifest));
            return Ok(RecoveryAction::Cooled);
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
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, row)?;
        tx.execute(
            "UPDATE transfers SET state='verifying',updated_at_ms=?2 WHERE transfer_id=?1",
            params![row.transfer, current_time_ms()],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;

        let part = self.part_path(row)?;
        let destination = self.final_path(row)?;
        if !part.exists() && destination.exists() {
            if !verify_file(&destination, manifest)? {
                return Err(AslError::InvalidMessage);
            }
        } else if destination.exists() {
            return Err(AslError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "download destination appeared during finalization",
            )));
        } else {
            fs::rename(&part, &destination)?;
        }
        if let Some(parent) = destination.parent() {
            sync_directory(parent)?;
        }
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        ensure_active_transfer(&tx, row)?;
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

    fn fail_with_cooldown(&mut self, row: &TransferRow, now: i64) -> Result<(), AslError> {
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        tx.execute(
            "INSERT INTO transfer_cooldowns(content_id,retry_after_ms,reason)
             VALUES (?1,?2,'full_hash_mismatch')
             ON CONFLICT(content_id) DO UPDATE SET
             retry_after_ms=excluded.retry_after_ms,reason=excluded.reason",
            params![row.content, now.saturating_add(DOWNLOAD_COOLDOWN_MS)],
        )
        .map_err(database_error)?;
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

    fn remove_staging(&self, row: &TransferRow) -> Result<(), AslError> {
        let _ = fs::remove_file(self.part_path(row)?);
        let _ = fs::remove_file(self.home.join(&row.manifest));
        Ok(())
    }

    fn record_bad_hash(&mut self, row: &TransferRow, peer: &PeerId) -> Result<(), AslError> {
        let peer = peer_text(peer);
        self.store
            .connection
            .execute(
                "UPDATE transfer_sources SET bad_hashes=bad_hashes+1,
                 state=CASE WHEN bad_hashes+1 >= 3 THEN 'banned' ELSE state END
                 WHERE transfer_id=?1 AND peer_id=?2",
                params![row.transfer, peer],
            )
            .map_err(database_error)?;
        self.store
            .connection
            .execute(
                "UPDATE transfer_chunks SET state='missing',source_peer=NULL,verified_at_ms=NULL
                 WHERE transfer_id=?1 AND source_peer=?2 AND state='assigned'",
                params![row.transfer, peer],
            )
            .map_err(database_error)?;
        Ok(())
    }

    fn lookup_source(&self, sources: &[PeerId]) -> Result<Option<String>, AslError> {
        let Some(peer) = sources.first() else {
            return Ok(None);
        };
        let text = peer_text(peer);
        let exists: bool = self
            .store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM peers WHERE peer_id=?1)",
                [&text],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !exists {
            return Err(AslError::NotFound);
        }
        Ok(Some(text))
    }

    fn load_row(&self, transfer_id: &TransferId) -> Result<TransferRow, AslError> {
        let transfer = id_text(transfer_id.0.0);
        self.store
            .connection
            .query_row(
                "SELECT t.transfer_id,t.task_id,t.content_id,t.write_grant_id,t.reservation_id,
                 t.part_relative,t.manifest_relative,t.state,t.durable_bytes,t.expires_at_ms,
                 r.state,w.root_path,w.status
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
        let bytes = fs::read(self.home.join(&row.manifest))?;
        decode_manifest(&bytes, parse_hash(&row.content)?).map_err(|_| AslError::InvalidDatabase)
    }

    fn part_path(&self, row: &TransferRow) -> Result<PathBuf, AslError> {
        safe_join(Path::new(&row.root), Path::new(&row.part))
    }

    fn final_path(&self, row: &TransferRow) -> Result<PathBuf, AslError> {
        let relative = row
            .part
            .strip_suffix(".part")
            .ok_or(AslError::InvalidDatabase)?;
        safe_join(Path::new(&row.root), Path::new(relative))
    }
}

#[derive(Clone, Debug)]
struct TransferRow {
    transfer: String,
    task: String,
    content: String,
    reservation: String,
    root: String,
    part: String,
    manifest: String,
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

fn check_download_limits(
    tx: &Transaction<'_>,
    requested: i64,
    unknown_source: bool,
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
    if unknown_source {
        let held: i64 = tx
            .query_row(
                "SELECT coalesce(sum(bytes),0) FROM reservations
                 WHERE kind='download' AND peer_id IS NULL AND state='held'",
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
                  AND t.state IN ('pending','running','verifying')
                  AND w.status='active'
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
         t.part_relative,t.manifest_relative,t.state,t.durable_bytes,t.expires_at_ms,
         r.state,w.root_path,w.status
         FROM transfers t JOIN reservations r USING(reservation_id)
         JOIN write_grants w ON w.write_grant_id=t.write_grant_id
         WHERE t.transfer_id=?1",
        [transfer],
        read_row,
    )
    .map_err(database_error)
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransferRow> {
    Ok(TransferRow {
        transfer: row.get(0)?,
        task: row.get(1)?,
        content: row.get(2)?,
        reservation: row.get(4)?,
        part: row.get(5)?,
        manifest: row.get(6)?,
        state: row.get(7)?,
        durable_bytes: row.get(8)?,
        expires_at_ms: row.get(9)?,
        reservation_state: row.get(10)?,
        root: row.get(11)?,
        grant_status: row.get(12)?,
    })
}

fn verify_durable_chunks(
    db: &rusqlite::Connection,
    row: &TransferRow,
    path: &Path,
    manifest: &Manifest,
) -> Result<usize, AslError> {
    let mut file = File::open(path)?;
    let mut statement = db
        .prepare(
            "SELECT chunk_index FROM transfer_chunks
             WHERE transfer_id=?1 AND state='durable' ORDER BY chunk_index",
        )
        .map_err(database_error)?;
    let indexes = statement
        .query_map([&row.transfer], |value| value.get::<_, u32>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let mut repaired = 0;
    for index in indexes {
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

fn durable_bytes(
    db: &rusqlite::Connection,
    transfer: &str,
    manifest: &Manifest,
) -> Result<i64, AslError> {
    let mut statement = db
        .prepare(
            "SELECT chunk_index FROM transfer_chunks
             WHERE transfer_id=?1 AND state='durable'",
        )
        .map_err(database_error)?;
    let indexes = statement
        .query_map([transfer], |value| value.get::<_, u32>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    indexes.into_iter().try_fold(0_i64, |total, index| {
        let length = chunk(manifest, index)?.len;
        total
            .checked_add(i64::try_from(length).map_err(|_| AslError::InvalidMessage)?)
            .ok_or(AslError::InvalidDatabase)
    })
}

fn verify_file(path: &Path, manifest: &Manifest) -> Result<bool, AslError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != manifest.file_size {
        return Ok(false);
    }
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

fn prepare_part(path: &Path, file_size: u64) -> Result<(), AslError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.set_len(file_size)?;
    file.sync_all()?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], length: Option<u64>) -> Result<(), AslError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    if let Some(length) = length {
        file.set_len(length)?;
    }
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), AslError> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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

fn random_id() -> Id128 {
    Id128(rand::random())
}

fn i64_time(value: u64) -> Result<i64, AslError> {
    i64::try_from(value).map_err(|_| AslError::InvalidMessage)
}
