//! Trusted local broker only. Importing a file does not grant disclosure.
mod grants;
mod index_input;
mod knowledge;
mod recovery;
mod reservations;
mod sources;

pub use knowledge::{DerivedResourceInfo, DerivedSource};
pub use recovery::RecoveryReport;

use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

use asl_policy::{
    AuthorizedFile, open_authorized_source,
    snapshot_files::{PinnedHome, SnapshotReader},
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    manifest::{Manifest, decode_manifest},
    protocol::{ConceptRef, SignedSemanticContextBundle},
    task::{GrantId, ResourceKey},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    Store, current_time_ms, database_error, open_store, semantic_context::SemanticContextResource,
};
use grants::ImportAuthority;
use reservations::Hold;

pub struct SnapshotBroker {
    store: Store,
    home: PathBuf,
    _pin: PinnedHome,
    reconcile_stop: Option<Arc<AtomicBool>>,
}

pub struct StoredSnapshotReader {
    reader: SnapshotReader,
    manifest_bytes: Vec<u8>,
    manifest: Manifest,
}

impl StoredSnapshotReader {
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn read_range(&mut self, offset: u64, length: u32) -> Result<Vec<u8>, AslError> {
        self.reader.read_range(offset, length)
    }
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

    pub fn semantic_context_resources(
        &self,
        reference: asl_types::protocol::SemanticContextRef,
    ) -> Result<Vec<SemanticContextResource>, AslError> {
        self.store.semantic_context_resources(reference)
    }

    pub fn open_snapshot(&self, content_id: Hash32) -> Result<StoredSnapshotReader, AslError> {
        let content = hex::encode(content_id.0);
        let metadata: Option<(String, i64, i64, String)> = self
            .store
            .connection
            .query_row(
                "SELECT file_hash,file_size,chunk_count,state FROM snapshots
                 WHERE content_id=?1",
                [&content],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(database_error)?;
        let (file_hash, file_size, chunk_count, state) = metadata.ok_or(AslError::NotFound)?;
        if state != "ready" {
            return Err(AslError::NotFound);
        }
        let mut reader = SnapshotReader::open(&self.home, content_id.0)?;
        let manifest_bytes = reader.read_manifest()?;
        let manifest = decode_manifest(&manifest_bytes, content_id.0)
            .map_err(|_| AslError::InvalidDatabase)?;
        let mut stored_file_hash = [0; 32];
        hex::decode_to_slice(file_hash, &mut stored_file_hash)
            .map_err(|_| AslError::InvalidDatabase)?;
        if manifest.file_hash != stored_file_hash
            || i64::try_from(manifest.file_size).ok() != Some(file_size)
            || i64::try_from(manifest.chunk_hashes.len()).ok() != Some(chunk_count)
            || reader.file_size()? != manifest.file_size
        {
            return Err(AslError::InvalidDatabase);
        }
        Ok(StoredSnapshotReader {
            reader,
            manifest_bytes,
            manifest,
        })
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
        let (mut staged, index, context_bytes) = {
            let db = &mut self.store.connection;
            index_input::copy_and_prepare(
                &self.home,
                source,
                Path::new(relative),
                source_is_context_package(relative),
                || progress(db),
            )?
        };
        let content_id = staged.content_id();
        let context_reference = context_bytes.and_then(|package_bytes| {
            let parsed = SignedSemanticContextBundle::decode(&package_bytes)
                .and_then(|signed| Ok((signed.bundle.context_ref()?, signed.encode()?)));
            let Ok((reference, canonical)) = parsed else {
                return None;
            };
            if canonical != package_bytes
                || self
                    .store
                    .put_semantic_context_candidate(&package_bytes, current_time_ms())
                    .is_err()
            {
                return None;
            }
            Some(reference)
        });
        let db = &mut self.store.connection;
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
        let existing: Option<(String, bool)> = tx
            .query_row(
                "SELECT resource_key, EXISTS(SELECT 1 FROM resource_fts f
                 WHERE f.rowid=resources.row_id AND f.resource_key=resources.resource_key)
             FROM resources WHERE grant_id=?1 AND source_relative=?2 AND active=1
             AND origin='local' AND source_file_id=?3 AND content_id=?4 AND source_grant_epoch=?5",
                params![auth.id, relative, source_id, content, auth.epoch],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let (key, indexed) = match existing {
            Some((key, indexed)) => (ResourceKey(parse_id(&key)?), indexed),
            None => {
                tx.execute("UPDATE resources SET active=0,updated_at_ms=?3 WHERE grant_id=?1 AND source_relative=?2 AND active=1 AND origin='local'",
                           params![auth.id,relative,now]).map_err(database_error)?;
                let key = ResourceKey(random_id());
                tx.execute("INSERT INTO resources(resource_key,content_id,grant_id,source_relative,source_file_id,origin,title,summary,evidence_status,created_at_ms,updated_at_ms,source_grant_epoch)
                    VALUES (?1,?2,?3,?4,?5,'local','','','source_backed',?6,?6,?7)",
                    params![hex::encode(key.0.0),content,auth.id,relative,source_id,now,auth.epoch]).map_err(database_error)?;
                bump_revision(&tx)?;
                (key, false)
            }
        };
        if !indexed {
            index.write(&tx, &key, content_id.into())?;
        }
        if let Some(reference) = context_reference {
            tx.execute(
                "INSERT OR IGNORE INTO semantic_context_resources(
                    resource_key,authority,namespace,revision,digest,content_id,file_size,indexed_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    hex::encode(key.0.0),
                    reference.authority.as_bytes(),
                    i64::from(reference.namespace),
                    i64::from(reference.revision),
                    reference.digest.as_bytes(),
                    content,
                    size,
                    now
                ],
            )
            .map_err(database_error)?;
        }
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

/// Returns DHT provider keys for resources whose source grant was explicitly
/// published. Only content and topic hashes leave the process; names, paths,
/// summaries and file lists stay local.
pub fn public_resource_provider_keys(store: &Store) -> Result<Vec<[u8; 32]>, AslError> {
    let mut statement = store
        .connection
        .prepare(
            "SELECT r.content_id,r.tags_json FROM resources r
             JOIN grants g ON g.grant_id=r.grant_id
             JOIN snapshots s ON s.content_id=r.content_id
             WHERE g.audience='public' AND g.status='active'
               AND g.epoch=r.source_grant_epoch
               AND r.active=1 AND s.state='ready'
             ORDER BY r.row_id LIMIT 4096",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(database_error)?;
    let mut keys = std::collections::BTreeSet::new();
    for row in rows {
        let (content, tags) = row.map_err(database_error)?;
        let content = parse_hash32(&content)?;
        keys.insert(domain_key(b"ASL-CONTENT-v1\0", content.as_bytes()));
        let tags: Vec<(u16, u32)> =
            serde_json::from_str(&tags).map_err(|_| AslError::InvalidDatabase)?;
        for (vocabulary_id, concept_id) in tags {
            let concept = ConceptRef {
                vocabulary_id,
                concept_id,
            };
            if concept.is_topic() {
                let mut value = [0; 6];
                value[..2].copy_from_slice(&concept.vocabulary_id.to_be_bytes());
                value[2..].copy_from_slice(&concept.concept_id.to_be_bytes());
                keys.insert(domain_key(b"ASL-CONCEPT-v1\0", &value));
            }
        }
    }
    Ok(keys.into_iter().collect())
}

fn domain_key(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

fn parse_hash32(value: &str) -> Result<Hash32, AslError> {
    if value.len() != 64 {
        return Err(AslError::InvalidDatabase);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(Hash32(bytes))
}

fn source_is_context_package(relative: &str) -> bool {
    Path::new(relative)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("aslc"))
}

fn immediate(conn: &mut Connection) -> Result<Transaction<'_>, AslError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)
}

pub(crate) fn bump_revision(conn: &Connection) -> Result<(), AslError> {
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
