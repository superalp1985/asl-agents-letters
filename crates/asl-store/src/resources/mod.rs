//! Trusted local broker only. Importing a file does not grant disclosure.
mod grants;
mod recovery;
mod reservations;
mod sources;

pub use recovery::RecoveryReport;

use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

use asl_policy::{
    AuthorizedFile, open_authorized_source,
    snapshot_files::{PinnedHome, StagedSnapshot},
};
use asl_types::{
    error::AslError,
    ids::Id128,
    task::{GrantId, ResourceKey},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{Store, current_time_ms, database_error, open_store};
use grants::ImportAuthority;
use reservations::Hold;

pub struct SnapshotBroker {
    store: Store,
    home: PathBuf,
    _pin: PinnedHome,
    reconcile_stop: Option<Arc<AtomicBool>>,
}

impl SnapshotBroker {
    /// `home` is the provisioned, private application root, not a shared grant.
    pub fn open(home: &Path) -> Result<Self, AslError> {
        let pin = PinnedHome::open(home)?;
        let store = open_store(&home.join("state").join("asl.sqlite3"))?;
        let mut broker = Self {
            store,
            home: home.to_owned(),
            _pin: pin,
            reconcile_stop: None,
        };
        broker.recover_expired_imports()?;
        Ok(broker)
    }

    pub fn set_reconcile_stop(&mut self, stop: Arc<AtomicBool>) {
        self.reconcile_stop = Some(stop);
    }

    pub fn import_source(
        &mut self,
        grant: &GrantId,
        relative: &Path,
    ) -> Result<ResourceKey, AslError> {
        self.import_with_progress(grant, relative, || Ok(()))
    }

    /// Local progress/cancellation hook; never invoked inside a DB write transaction.
    pub fn import_with_progress(
        &mut self,
        grant: &GrantId,
        relative: &Path,
        progress: impl FnMut() -> Result<(), AslError>,
    ) -> Result<ResourceKey, AslError> {
        let authority = self.import_authority(grant)?;
        let mut source = open_authorized_source(&authority.restore(&self.home)?, relative)?;
        // open_authorized_source validated the complete spelling, including separators.
        let relative = relative
            .to_str()
            .ok_or(AslError::NotFound)?
            .replace('/', "\\");
        let hold = self.reserve(&authority, source.len())?;
        let result = self.copy_and_commit(&authority, &hold, &relative, &mut source, progress);
        if result.is_err() && !matches!(result, Err(AslError::SnapshotRecoveryRequired)) {
            self.release(&hold)?;
        }
        result
    }

    fn copy_and_commit(
        &mut self,
        auth: &ImportAuthority,
        hold: &Hold,
        relative: &str,
        source: &mut AuthorizedFile,
        mut observer: impl FnMut() -> Result<(), AslError>,
    ) -> Result<ResourceKey, AslError> {
        let mut last_progress = Instant::now();
        let mut progress = |db: &mut Connection| {
            observer()?;
            if last_progress.elapsed() >= Duration::from_secs(1) {
                reservations::progress(db, hold)?;
                last_progress = Instant::now();
            }
            Ok(())
        };
        let db = &mut self.store.connection;
        let mut staged = StagedSnapshot::copy_from(&self.home, source, || progress(db))?;
        let content_id = staged.content_id();
        recovery::claim_install(db, hold, content_id)?;
        // New objects stay exclusively pinned. Do not hold a SQLite writer
        // while copying or verifying a large blob; the rows are the visibility gate.
        staged.install_with_progress(|| progress(db))?;
        let tx = immediate(&mut self.store.connection)?;
        let now = current_time_ms();
        reservations::check_live(&tx, hold, now)?;
        reservations::check_current_limits(&tx, hold)?;
        let content = hex::encode(staged.content_id());
        let hash = hex::encode(staged.manifest().file_hash);
        let size =
            i64::try_from(staged.manifest().file_size).map_err(|_| AslError::InvalidPolicyState)?;
        let chunks = staged.manifest().chunk_hashes.len() as i64;
        let blob = format!("snapshots/{}/{content}.blob", &content[..2]);
        let manifest = format!("manifests/{}/{content}.mnf", &content[..2]);
        let source_id = grants::file_id(source.identity());

        let written = tx.execute(
            "INSERT INTO snapshots(content_id,file_hash,file_size,chunk_count,blob_relative,manifest_relative,state,created_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,'ready',?7)
             ON CONFLICT(content_id) DO UPDATE SET state='ready' WHERE snapshots.state='ready'
               AND file_hash=excluded.file_hash AND file_size=excluded.file_size AND chunk_count=excluded.chunk_count
               AND blob_relative=excluded.blob_relative AND manifest_relative=excluded.manifest_relative",
            params![content,hash,size,chunks,blob,manifest,now]).map_err(database_error)?;
        if written != 1 {
            return Err(AslError::InvalidDatabase);
        }
        let existing: Option<String> = tx.query_row(
            "SELECT resource_key FROM resources WHERE grant_id=?1 AND source_relative=?2 AND active=1
             AND origin='local' AND source_file_id=?3 AND content_id=?4 AND source_grant_epoch=?5",
            params![auth.id,relative,source_id,content,auth.epoch], |r|r.get(0)).optional().map_err(database_error)?;
        let key = match existing {
            Some(key) => ResourceKey(parse_id(&key)?),
            None => {
                tx.execute("UPDATE resources SET active=0,updated_at_ms=?3 WHERE grant_id=?1 AND source_relative=?2 AND active=1 AND origin='local'",
                           params![auth.id,relative,now]).map_err(database_error)?;
                let key = ResourceKey(random_id());
                tx.execute("INSERT INTO resources(resource_key,content_id,grant_id,source_relative,source_file_id,origin,title,summary,evidence_status,created_at_ms,updated_at_ms,source_grant_epoch)
                    VALUES (?1,?2,?3,?4,?5,'local','','','source_backed',?6,?6,?7)",
                    params![hex::encode(key.0.0),content,auth.id,relative,source_id,now,auth.epoch]).map_err(database_error)?;
                bump_revision(&tx)?;
                key
            }
        };
        reservations::finish(&tx, hold, "consumed", "done")?;
        if let Err(error) = tx.execute_batch("COMMIT") {
            if !tx.is_autocommit() && tx.rollback().is_ok() {
                return Err(database_error(error));
            }
            // The durable outcome is unknown. Only recovery may unlink.
            staged.retain_installed();
            return Err(AslError::SnapshotRecoveryRequired);
        }
        staged.retain_installed();
        Ok(key)
    }
}

fn immediate(conn: &mut Connection) -> Result<Transaction<'_>, AslError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)
}

fn bump_revision(conn: &Connection) -> Result<(), AslError> {
    conn.execute(
        "UPDATE policy_state SET revision=revision+1 WHERE singleton=1",
        [],
    )
    .map_err(database_error)?;
    Ok(())
}

fn random_id() -> Id128 {
    Id128(rand::random())
}

fn parse_id(text: &str) -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(Id128(bytes))
}
