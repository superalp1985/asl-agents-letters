use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
};

use asl_policy::{
    AccessOperation, FileIdentity, Permit, PolicyService, Principal, WriteGrant,
    snapshot_files::StagedSnapshot,
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    protocol::ConceptRef,
    task::{GrantId, ResourceKey, TaskId},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{SnapshotBroker, bump_revision, current_time_ms, database_error, immediate, random_id};
use crate::search::{LocalIndexText, PreparedIndex};

const MAX_DERIVED_BYTES: usize = 32 * 1024;
const MAX_DIRECT_SOURCES: usize = 8;
const MAX_PROVENANCE_DEPTH: usize = 4;
const MAX_LEAF_REFERENCES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedSource {
    pub resource_key: ResourceKey,
    pub grant_id: GrantId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedResourceInfo {
    pub resource_key: ResourceKey,
    pub content_id: Hash32,
    pub published: bool,
}

impl SnapshotBroker {
    /// Registers an independently authorized destination, pinned to its directory identity.
    pub fn authorize_derived_directory(
        &mut self,
        root: &Path,
        max_bytes: u64,
    ) -> Result<Id128, AslError> {
        self.authorize_write_directory(root, max_bytes, "derived")
    }

    /// Registers the user-selected inbox where received files may be created.
    pub fn authorize_inbox_directory(
        &mut self,
        root: &Path,
        max_bytes: u64,
    ) -> Result<Id128, AslError> {
        self.authorize_write_directory(root, max_bytes, "inbox")
    }

    fn authorize_write_directory(
        &mut self,
        root: &Path,
        max_bytes: u64,
        kind: &str,
    ) -> Result<Id128, AslError> {
        let max_bytes = i64::try_from(max_bytes).map_err(|_| AslError::QuotaExceeded)?;
        let path = root.to_str().ok_or(AslError::InvalidStorageRoot)?;
        let protected = write_protected_root(&self.home, root);
        let capability = WriteGrant::open(root, &protected)?;
        let identity = capability.identity();
        let id = random_id();
        let tx = immediate(&mut self.store.connection)?;
        tx.execute(
            "INSERT INTO write_grants(
                write_grant_id,kind,root_path,max_bytes,epoch,status,root_volume,root_file_id
             ) VALUES (?1,?2,?3,?4,1,'active',?5,?6)",
            params![
                hex::encode(id.0),
                kind,
                path,
                max_bytes,
                format!("{:016x}", identity.volume_serial),
                hex::encode(identity.file_id)
            ],
        )
        .map_err(database_error)?;
        bump_revision(&tx)?;
        tx.commit().map_err(database_error)?;
        Ok(id)
    }

    pub fn revoke_inbox_directory(&mut self, id: Id128) -> Result<(), AslError> {
        let tx = immediate(&mut self.store.connection)?;
        let changed = tx
            .execute(
                "UPDATE write_grants
                 SET status='revoked',epoch=epoch+1
                 WHERE write_grant_id=?1 AND kind='inbox' AND status='active'",
                [hex::encode(id.0)],
            )
            .map_err(database_error)?;
        if changed != 0 {
            bump_revision(&tx)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn revoke_derived_directory(&mut self, id: Id128) -> Result<(), AslError> {
        let id_text = hex::encode(id.0);
        let tx = immediate(&mut self.store.connection)?;
        let changed = tx
            .execute(
                "UPDATE write_grants
                 SET status='revoked',epoch=epoch+1
                 WHERE write_grant_id=?1 AND kind='derived' AND status='active'",
                [&id_text],
            )
            .map_err(database_error)?;
        if changed != 0 {
            tx.execute(
                "WITH RECURSIVE descendants(resource_key) AS (
                    SELECT resource_key FROM derived_write_refs WHERE write_grant_id=?1
                    UNION
                    SELECT d.derived_resource_key
                    FROM derivation_sources d JOIN descendants x
                      ON d.source_resource_key=x.resource_key
                 )
                 UPDATE resources SET active=0,updated_at_ms=?2
                 WHERE origin='derived' AND active=1
                   AND resource_key IN (SELECT resource_key FROM descendants)",
                params![id_text, current_time_ms()],
            )
            .map_err(database_error)?;
            bump_revision(&tx)?;
        }
        tx.commit().map_err(database_error)
    }

    /// Returns only active, ready sources with a current durable grant.
    pub fn derived_sources(&self, keys: &[ResourceKey]) -> Result<Vec<DerivedSource>, AslError> {
        validate_source_list(keys)?;
        let mut leaves = 0;
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            validate_source_graph(
                &self.store.connection,
                key,
                1,
                &mut HashSet::new(),
                &mut leaves,
            )?;
            let (grant, origin): (Option<String>, String) = self
                .store
                .connection
                .query_row(
                    "SELECT r.grant_id,r.origin FROM resources r
                     JOIN snapshots s USING(content_id)
                     WHERE r.resource_key=?1 AND r.active=1 AND s.state='ready'",
                    [hex::encode(key.0.0)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(database_error)?
                .ok_or(AslError::NotFound)?;
            let grant = grant.ok_or(AslError::PolicyDenied)?;
            let grant_id = GrantId(parse_id(&grant)?);
            if origin == "local" || origin == "derived" {
                let current: bool = self
                    .store
                    .connection
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM resources r JOIN grants g USING(grant_id)
                            WHERE r.resource_key=?1 AND g.status='active'
                              AND r.source_grant_epoch=g.epoch
                        )",
                        [hex::encode(key.0.0)],
                        |row| row.get(0),
                    )
                    .map_err(database_error)?;
                if !current {
                    return Err(AslError::GrantRevoked);
                }
            }
            result.push(DerivedSource {
                resource_key: key.clone(),
                grant_id,
            });
        }
        Ok(result)
    }

    /// Stores a validated, typed local record. The model never supplies labels,
    /// paths, grant IDs, timestamps, or verification status.
    #[allow(clippy::too_many_arguments)]
    pub fn save_derived_knowledge(
        &mut self,
        write_grant_id: Id128,
        task_id: &TaskId,
        bytes: &[u8],
        sources: &[ResourceKey],
        concepts: &[ConceptRef],
        write_permits: &[Permit],
        publish_permits: &[Permit],
        policy: &dyn PolicyService,
        now_ms: u64,
    ) -> Result<DerivedResourceInfo, AslError> {
        if bytes.is_empty()
            || bytes.len() > MAX_DERIVED_BYTES
            || std::str::from_utf8(bytes).is_err()
            || now_ms > i64::MAX as u64
            || concepts.len() > 64
            || concepts.iter().any(|concept| !concept.is_known())
            || concepts
                .iter()
                .enumerate()
                .any(|(index, concept)| concepts[..index].contains(concept))
        {
            return Err(AslError::InvalidMessage);
        }

        let source_facts = self.derived_sources(sources)?;
        validate_permit_set(
            &source_facts,
            task_id,
            AccessOperation::WriteDerived,
            write_permits,
            true,
        )?;
        validate_permit_set(
            &source_facts,
            task_id,
            AccessOperation::PublishRecord,
            publish_permits,
            false,
        )?;

        let write_id = hex::encode(write_grant_id.0);
        let (root, max_bytes, epoch, volume, file_id): (String, i64, i64, String, String) = self
            .store
            .connection
            .query_row(
                "SELECT root_path,max_bytes,epoch,root_volume,root_file_id
                 FROM write_grants
                 WHERE write_grant_id=?1 AND kind='derived' AND status='active'",
                [&write_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::PolicyDenied)?;
        let size = i64::try_from(bytes.len()).map_err(|_| AslError::QuotaExceeded)?;
        if size > max_bytes {
            return Err(AslError::QuotaExceeded);
        }
        let identity = FileIdentity {
            volume_serial: u64::from_str_radix(&volume, 16)
                .map_err(|_| AslError::InvalidDatabase)?,
            file_id: parse_id(&file_id)?.0,
        };
        let root_path = PathBuf::from(&root);
        let protected = write_protected_root(&self.home, &root_path);
        let write_root = WriteGrant::restore(&root_path, &protected, &identity)?;
        let resource_key = ResourceKey(random_id());
        let relative_name = format!("{}.json", hex::encode(resource_key.0.0));
        let mut output = write_root.create_new(Path::new(&relative_name))?;
        output.write_all(bytes)?;
        output.sync_all()?;

        let mut staged = StagedSnapshot::from_bytes(&self.home, bytes)?;
        staged.install()?;
        let content_id = Hash32(staged.content_id());
        let content = hex::encode(content_id.0);
        let file_hash = hex::encode(staged.manifest().file_hash);
        let chunk_count = i64::try_from(staged.manifest().chunk_hashes.len())
            .map_err(|_| AslError::QuotaExceeded)?;
        let title = "Derived knowledge";
        let body = std::str::from_utf8(bytes).map_err(|_| AslError::InvalidMessage)?;
        let index = PreparedIndex::new(LocalIndexText {
            title,
            summary: "",
            body,
            concepts,
        })?;
        let snapshot_blob = format!("snapshots/{}/{content}.blob", &content[..2]);
        let snapshot_manifest = format!("manifests/{}/{content}.mnf", &content[..2]);

        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        verify_write_grant(&tx, &write_id, &root, max_bytes, epoch, &volume, &file_id)?;
        check_write_quota(&tx, &write_id, size, max_bytes)?;
        let current_sources = load_sources(&tx, sources)?;
        validate_source_permits(&current_sources, &source_facts, task_id, write_permits)?;
        for permit in write_permits {
            policy.revalidate(permit, now_ms)?;
        }
        let published = publish_permits.len() == sources.len()
            && publish_permits
                .iter()
                .all(|permit| policy.revalidate(permit, now_ms).is_ok());
        if !published {
            for permit in publish_permits {
                if !source_facts.iter().any(|source| {
                    permit_matches(permit, source, task_id, AccessOperation::PublishRecord)
                }) {
                    return Err(AslError::PolicyDenied);
                }
            }
        }

        if current_sources.is_empty() {
            return Err(AslError::NotFound);
        }
        let grant_id = GrantId(random_id());
        let grant_text = hex::encode(grant_id.0.0);
        let id_text = hex::encode(resource_key.0.0);
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let labels = serde_json::to_string(&serde_json::json!({
            "kind": if published { "public" } else { "private" },
            "disclosure_allowed": published
        }))
        .map_err(|_| AslError::InvalidMessage)?;
        let extensions = r#"["json"]"#;
        let audience = if published { "public" } else { "peers" };
        let bytes_limit = i64::try_from(bytes.len()).map_err(|_| AslError::QuotaExceeded)?;

        let snapshot_row = tx.execute(
            "INSERT INTO snapshots(
                content_id,file_hash,file_size,chunk_count,blob_relative,manifest_relative,state,created_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,'ready',?7)
             ON CONFLICT(content_id) DO UPDATE SET state='ready'
             WHERE snapshots.state='ready' AND file_hash=excluded.file_hash
               AND file_size=excluded.file_size AND chunk_count=excluded.chunk_count
               AND blob_relative=excluded.blob_relative
               AND manifest_relative=excluded.manifest_relative",
            params![
                content,
                file_hash,
                size,
                chunk_count,
                snapshot_blob,
                snapshot_manifest,
                now
            ],
        ).map_err(database_error)?;
        if snapshot_row != 1 {
            return Err(AslError::InvalidDatabase);
        }
        tx.execute(
            "INSERT INTO grants(
                grant_id,root_path,volume_id,root_file_id,extensions_json,audience,
                group_id,model_policy,max_snapshot_bytes,epoch,status,created_at_ms,
                allow_derived_disclosure
             ) VALUES (?1,?2,?3,?4,?5,?6,NULL,'never',?7,1,'active',?8,?9)",
            params![
                grant_text,
                root,
                volume,
                file_id,
                extensions,
                audience,
                bytes_limit,
                now,
                published
            ],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO resources(
                resource_key,content_id,grant_id,source_relative,source_file_id,
                origin,title,summary,tags_json,label_json,evidence_status,active,
                created_at_ms,updated_at_ms,source_grant_epoch
             ) VALUES (?1,?2,?3,?4,NULL,'derived',?5,'','[]',?6,
                       'derived_unverified',1,?7,?7,1)",
            params![
                id_text,
                content,
                grant_text,
                relative_name,
                title,
                labels,
                now
            ],
        )
        .map_err(database_error)?;
        for source in sources {
            tx.execute(
                "INSERT INTO derivation_sources(derived_resource_key,source_resource_key)
                 VALUES (?1,?2)",
                params![id_text, hex::encode(source.0.0)],
            )
            .map_err(database_error)?;
        }
        tx.execute(
            "INSERT INTO derived_write_refs(
                resource_key,write_grant_id,relative_name,file_size,created_at_ms
             ) VALUES (?1,?2,?3,?4,?5)",
            params![id_text, write_id, relative_name, size, now],
        )
        .map_err(database_error)?;
        index.write(&tx, &resource_key, content_id)?;
        bump_revision(&tx)?;
        if let Err(error) = tx.execute_batch("COMMIT") {
            if !tx.is_autocommit() && tx.rollback().is_ok() {
                return Err(database_error(error));
            }
            staged.retain_installed();
            output.retain();
            return Err(AslError::SnapshotRecoveryRequired);
        }
        staged.retain_installed();
        output.retain();
        Ok(DerivedResourceInfo {
            resource_key,
            content_id,
            published,
        })
    }
}

pub(super) fn invalidate_derived_for_grant(
    db: &rusqlite::Connection,
    grant_id: &str,
    now_ms: i64,
) -> Result<(), AslError> {
    db.execute(
        "WITH RECURSIVE descendants(resource_key) AS (
            SELECT resource_key FROM resources WHERE grant_id=?1
            UNION
            SELECT d.derived_resource_key FROM derivation_sources d
            JOIN descendants x ON d.source_resource_key=x.resource_key
         )
         UPDATE resources SET active=0,updated_at_ms=?2
         WHERE origin='derived' AND active=1
           AND resource_key IN (SELECT resource_key FROM descendants)",
        params![grant_id, now_ms],
    )
    .map_err(database_error)?;
    Ok(())
}

pub(super) fn invalidate_derived_from(
    db: &rusqlite::Connection,
    source: &ResourceKey,
    now_ms: i64,
) -> Result<(), AslError> {
    db.execute(
        "WITH RECURSIVE descendants(resource_key) AS (
            SELECT ?1
            UNION
            SELECT d.derived_resource_key FROM derivation_sources d
            JOIN descendants x ON d.source_resource_key=x.resource_key
         )
         UPDATE resources SET active=0,updated_at_ms=?2
         WHERE origin='derived' AND active=1
           AND resource_key IN (SELECT resource_key FROM descendants)",
        params![hex::encode(source.0.0), now_ms],
    )
    .map_err(database_error)?;
    Ok(())
}

fn verify_write_grant(
    db: &rusqlite::Transaction<'_>,
    id: &str,
    root: &str,
    max_bytes: i64,
    epoch: i64,
    volume: &str,
    file_id: &str,
) -> Result<(), AslError> {
    let active: bool = db
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM write_grants
                WHERE write_grant_id=?1 AND kind='derived' AND status='active'
                  AND root_path=?2 AND max_bytes=?3 AND epoch=?4
                  AND root_volume=?5 AND root_file_id=?6
            )",
            params![id, root, max_bytes, epoch, volume, file_id],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if active {
        Ok(())
    } else {
        Err(AslError::PolicyDenied)
    }
}

fn check_write_quota(
    db: &rusqlite::Transaction<'_>,
    id: &str,
    requested: i64,
    maximum: i64,
) -> Result<(), AslError> {
    let used: i64 = db
        .query_row(
            "SELECT coalesce(sum(file_size),0)
             FROM derived_write_refs WHERE write_grant_id=?1",
            [id],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if used
        .checked_add(requested)
        .is_some_and(|total| total <= maximum)
    {
        Ok(())
    } else {
        Err(AslError::QuotaExceeded)
    }
}

fn validate_permit_set(
    sources: &[DerivedSource],
    task: &TaskId,
    operation: AccessOperation,
    permits: &[Permit],
    require_all: bool,
) -> Result<(), AslError> {
    if (require_all && permits.len() != sources.len()) || permits.len() > sources.len() {
        return Err(AslError::PolicyDenied);
    }
    let mut seen = HashSet::new();
    for permit in permits {
        let Some(source) = sources
            .iter()
            .find(|source| permit_matches(permit, source, task, operation))
        else {
            return Err(AslError::PolicyDenied);
        };
        if !seen.insert(source.resource_key.clone()) {
            return Err(AslError::PolicyDenied);
        }
    }
    Ok(())
}

fn permit_matches(
    permit: &Permit,
    source: &DerivedSource,
    task: &TaskId,
    operation: AccessOperation,
) -> bool {
    permit.resource_key() == &source.resource_key
        && permit.grant_id() == &source.grant_id
        && permit.principal() == &Principal::LocalTask(task.clone())
        && permit.operation() == operation
}

fn validate_source_permits(
    current: &[DerivedSource],
    expected: &[DerivedSource],
    task: &TaskId,
    permits: &[Permit],
) -> Result<(), AslError> {
    if current != expected {
        return Err(AslError::PolicyVersionConflict);
    }
    validate_permit_set(current, task, AccessOperation::WriteDerived, permits, true)
}

fn load_sources(
    db: &rusqlite::Transaction<'_>,
    keys: &[ResourceKey],
) -> Result<Vec<DerivedSource>, AslError> {
    let mut result = Vec::with_capacity(keys.len());
    let mut leaves = 0;
    for key in keys {
        validate_source_graph(db, key, 1, &mut HashSet::new(), &mut leaves)?;
        let grant: Option<String> = db
            .query_row(
                "SELECT r.grant_id FROM resources r
                 JOIN snapshots s USING(content_id)
                 WHERE r.resource_key=?1 AND r.active=1 AND s.state='ready'",
                [hex::encode(key.0.0)],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?
            .flatten();
        result.push(DerivedSource {
            resource_key: key.clone(),
            grant_id: GrantId(parse_id(&grant.ok_or(AslError::PolicyDenied)?)?),
        });
    }
    Ok(result)
}

struct SourceGraphRow {
    origin: String,
    active: bool,
    ready: bool,
    grant_status: Option<String>,
    grant_epoch: Option<i64>,
    resource_epoch: Option<i64>,
}

fn validate_source_graph(
    db: &rusqlite::Connection,
    key: &ResourceKey,
    depth: usize,
    path: &mut HashSet<ResourceKey>,
    leaves: &mut usize,
) -> Result<(), AslError> {
    if depth > MAX_PROVENANCE_DEPTH || !path.insert(key.clone()) {
        return Err(AslError::PolicyDenied);
    }
    let row: Option<SourceGraphRow> = db
        .query_row(
            "SELECT r.origin,r.active,s.state='ready',g.status,g.epoch,r.source_grant_epoch
             FROM resources r JOIN snapshots s USING(content_id)
             LEFT JOIN grants g ON g.grant_id=r.grant_id
             WHERE r.resource_key=?1",
            [hex::encode(key.0.0)],
            |row| {
                Ok(SourceGraphRow {
                    origin: row.get(0)?,
                    active: row.get(1)?,
                    ready: row.get(2)?,
                    grant_status: row.get(3)?,
                    grant_epoch: row.get(4)?,
                    resource_epoch: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(database_error)?;
    let Some(row) = row else {
        return Err(AslError::NotFound);
    };
    if !row.active
        || !row.ready
        || (matches!(row.origin.as_str(), "local" | "derived")
            && !(row.grant_status.as_deref() == Some("active")
                && row.grant_epoch == row.resource_epoch))
    {
        return Err(AslError::GrantRevoked);
    }
    if row.origin == "derived" {
        let mut statement = db
            .prepare(
                "SELECT source_resource_key FROM derivation_sources
                 WHERE derived_resource_key=?1 ORDER BY source_resource_key",
            )
            .map_err(database_error)?;
        let sources = statement
            .query_map([hex::encode(key.0.0)], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if sources.is_empty() || sources.len() > MAX_DIRECT_SOURCES {
            return Err(AslError::PolicyDenied);
        }
        for source in sources {
            validate_source_graph(
                db,
                &ResourceKey(parse_id(&source)?),
                depth + 1,
                path,
                leaves,
            )?;
        }
    } else {
        *leaves += 1;
        if *leaves > MAX_LEAF_REFERENCES {
            return Err(AslError::PolicyDenied);
        }
    }
    path.remove(key);
    Ok(())
}

fn validate_source_list(keys: &[ResourceKey]) -> Result<(), AslError> {
    if keys.is_empty()
        || keys.len() > MAX_DIRECT_SOURCES
        || keys
            .iter()
            .enumerate()
            .any(|(index, key)| keys[..index].contains(key))
    {
        return Err(AslError::PolicyDenied);
    }
    Ok(())
}

fn parse_id(value: &str) -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(Id128(bytes))
}

fn write_protected_root(home: &Path, root: &Path) -> PathBuf {
    if root == home.join("derived") || root == home.join("inbox") {
        home.join("state")
    } else {
        home.to_owned()
    }
}
