//! Core-only bridge from a live direct admission and durable grants to scoped search.
use std::{collections::HashSet, path::Path, time::Duration};

use asl_policy::{
    AccessOperation, Audience, AuthenticatedDevice, GrantPolicy, ModelPolicy, Permit,
    PolicyRevision, PolicySnapshot, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    task::{GrantId, GroupId, ResourceKey},
};
use rusqlite::{
    Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params,
};

use super::{
    MAX_KEYS, identity_revision,
    scope::{AUTHORITY, bytes},
};
use crate::{Store, chain::agent_text, current_time_ms, database_error, open_store};

/// Supplied by the Core only, from the original authenticated connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectRequester {
    pub agent: AgentId,
    pub peer: PeerId,
    pub session_expires_at_ms: u64,
    pub registry_sequence: u64,
    pub directory_commitment: [u8; 32],
    pub controller: [u8; 20],
}

/// A separate connection keeps interactive query lock waits out of the import broker.
pub fn open_direct_store(path: &Path) -> Result<Store, AslError> {
    let store = open_store(path)?;
    store
        .connection
        .busy_timeout(Duration::from_millis(25))
        .map_err(database_error)?;
    Ok(store)
}

impl Store {
    pub fn direct_search_snapshot(
        &self,
        requester: &DirectRequester,
    ) -> Result<(PolicySnapshot, Vec<ResourceKey>), AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let revision = direct_revision(&tx, requester)?;
        // Apply the durable recipient audience before the bounded candidate
        // window so private rows cannot starve resources this peer may search.
        let mut statement = tx
            .prepare_cached(&format!(
                "SELECT f.rowid FROM resource_fts f
             CROSS JOIN resources r ON r.row_id=f.rowid AND r.resource_key=f.resource_key
             {AUTHORITY} AND g.audience<>'group'
             ORDER BY f.rowid DESC LIMIT ?3"
            ))
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    agent_text(requester.agent),
                    bs58::encode(requester.peer.as_bytes()).into_string(),
                    MAX_KEYS as i64 + 1
                ],
                |row| row.get::<_, i64>(0),
            )
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        drop(statement);
        if rows.len() > MAX_KEYS {
            return Err(AslError::QuotaExceeded);
        }
        let ids = serde_json::to_string(&rows).map_err(|_| AslError::InvalidPolicyState)?;
        let mut snapshot = PolicySnapshot {
            revision,
            ..PolicySnapshot::default()
        };
        // The live admission gate checks chain freshness; the policy permit is
        // additionally capped by the directory/certificate lifetime of that session.
        snapshot.devices.insert(
            requester.peer.clone(),
            AuthenticatedDevice {
                agent_id: requester.agent,
                active: true,
                chain_valid_until_ms: requester.session_expires_at_ms,
                certificate_valid_until_ms: requester.session_expires_at_ms,
            },
        );
        let mut keys = Vec::new();
        visit_direct_rows(&tx, requester, "row_id", &ids, |row| {
            keys.push(row.key.clone());
            snapshot
                .grants
                .insert(row.resource.grant_id.clone(), row.grant);
            snapshot.resources.insert(row.key, row.resource);
            for (key, resource, grant) in row.dependencies {
                snapshot.grants.insert(resource.grant_id.clone(), grant);
                snapshot.resources.insert(key, resource);
            }
        })?;
        let is_contact: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authorized_contacts WHERE agent_id=?1)",
                [agent_text(requester.agent)],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if is_contact {
            snapshot.contacts.insert(requester.agent);
        }
        tx.commit().map_err(database_error)?;
        Ok((snapshot, keys))
    }

    /// Serializes the final disclosure with durable authorization writes. The
    /// callback only queues the already-encoded reply to the local Net process.
    pub fn with_current_direct_authority<T>(
        &self,
        requester: &DirectRequester,
        expected_revision: PolicyRevision,
        permit: Option<&Permit>,
        root_task_id: Option<Id128>,
        enqueue: impl FnOnce() -> Result<T, AslError>,
    ) -> Result<T, AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(|error| match error.sqlite_error_code() {
                Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
                    AslError::PolicyVersionConflict
                }
                _ => database_error(error),
            })?;
        if direct_revision(&tx, requester)? != expected_revision {
            return Err(AslError::PolicyVersionConflict);
        }
        if let Some(permit) = permit {
            if permit.requester_agent_id() != Some(requester.agent)
                || permit.authenticated_device_peer_id() != Some(&requester.peer)
                || !matches!(
                    permit.operation(),
                    AccessOperation::ReadMetadata | AccessOperation::ReadChunk
                )
                || permit.group_binding().is_some()
                || permit.policy_revision() != expected_revision
                || permit.expires_at_ms() <= current_time_ms() as u64
            {
                return Err(AslError::NotFound);
            }
            let ids = serde_json::to_string(&[hex::encode(permit.resource_key().0.0)])
                .map_err(|_| AslError::InvalidPolicyState)?;
            let mut allowed = false;
            visit_direct_rows(&tx, requester, "resource_key", &ids, |row| {
                allowed = &row.resource.grant_id == permit.grant_id()
                    && row.resource.grant_epoch == permit.grant_epoch()
                    && row.resource.content_id == permit.content_id()
                    && row.resource.file_size == permit.file_size();
            })?;
            if !allowed {
                return Err(AslError::NotFound);
            }
        }
        if let Some(root_task_id) = root_task_id {
            let updated = tx
                .execute(
                    "UPDATE direct_inbound_conversations SET messages_used=messages_used+1
                 WHERE agent_id=?1 AND root_task_id=?2 AND expires_at_ms>?3
                   AND rounds_used<=3 AND messages_used<6",
                    params![
                        agent_text(requester.agent),
                        hex::encode(root_task_id.0),
                        current_time_ms()
                    ],
                )
                .map_err(database_error)?;
            if updated != 1 {
                return Err(AslError::QuotaExceeded);
            }
        }
        tx.commit().map_err(database_error)?;
        // The caller performs only an in-process bounded queue try-send after
        // durable authorization and message-budget reservation commit.
        enqueue()
    }
}

pub(super) struct DirectRow {
    pub key: ResourceKey,
    pub resource: ResourcePolicy,
    pub grant: GrantPolicy,
    pub dependencies: Vec<(ResourceKey, ResourcePolicy, GrantPolicy)>,
}

pub(super) fn direct_revision(
    db: &Connection,
    requester: &DirectRequester,
) -> Result<PolicyRevision, AslError> {
    if requester.session_expires_at_ms <= current_time_ms() as u64 {
        return Err(AslError::NotFound);
    }
    let sequence = i64::try_from(requester.registry_sequence).map_err(|_| AslError::NotFound)?;
    let current: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM identity_registry_states
         WHERE agent_id=?1 AND status='active' AND sequence=?2
           AND state_commitment=?3 AND controller_address=?4)",
            params![
                agent_text(requester.agent),
                sequence,
                requester.directory_commitment.as_slice(),
                requester.controller.as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !current {
        return Err(AslError::NotFound);
    }
    identity_revision(db, requester.agent, &requester.peer).map(PolicyRevision)
}

fn visit_direct_rows(
    db: &Connection,
    requester: &DirectRequester,
    lookup: &'static str,
    ids: &str,
    mut visit: impl FnMut(DirectRow),
) -> Result<(), AslError> {
    let mut statement = db
        .prepare_cached(&format!(
            "SELECT r.resource_key
         FROM json_each(?3) k CROSS JOIN resources r ON r.{lookup}=k.value
         {AUTHORITY} AND g.audience<>'group'"
        ))
        .map_err(database_error)?;
    let keys = statement
        .query_map(
            params![
                agent_text(requester.agent),
                bs58::encode(requester.peer.as_bytes()).into_string(),
                ids
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    drop(statement);
    for key in keys {
        let key = ResourceKey(Id128(bytes(&key)?));
        let Some(node) = load_policy_node(db, requester, None, &key, 0, &mut HashSet::new())?
        else {
            continue;
        };
        let mut dependencies = Vec::new();
        flatten_dependencies(&node, &mut dependencies);
        visit(DirectRow {
            key: node.key,
            resource: node.resource,
            grant: node.grant,
            dependencies,
        });
    }
    Ok(())
}

pub(super) struct PolicyNode {
    pub(super) key: ResourceKey,
    pub(super) resource: ResourcePolicy,
    pub(super) grant: GrantPolicy,
    sources: Vec<PolicyNode>,
}

struct DirectPolicyRow {
    resource_key: String,
    content_id: String,
    grant_id: Option<String>,
    grant_epoch: Option<i64>,
    file_size: i64,
    source_relative: Option<String>,
    extensions_json: String,
    audience: String,
    max_snapshot_bytes: Option<i64>,
    allow_derived_disclosure: i64,
    origin: String,
    active: i64,
    label_json: String,
    snapshot_state: String,
    grant_status: Option<String>,
    source_grant_epoch: Option<i64>,
    group_id: Option<String>,
}

pub(super) fn load_policy_node(
    db: &Connection,
    requester: &DirectRequester,
    group_scope: Option<&GroupId>,
    key: &ResourceKey,
    depth: usize,
    path: &mut HashSet<ResourceKey>,
) -> Result<Option<PolicyNode>, AslError> {
    if depth > 4 || !path.insert(key.clone()) {
        return Err(AslError::NotFound);
    }
    let row: Option<DirectPolicyRow> = db
        .query_row(
            "SELECT r.resource_key,r.content_id,r.grant_id,g.epoch,s.file_size,
                    r.source_relative,g.extensions_json,g.audience,g.max_snapshot_bytes,
                    g.allow_derived_disclosure,r.origin,r.active,r.label_json,s.state,
                    g.status,r.source_grant_epoch,g.group_id
             FROM resources r JOIN snapshots s USING(content_id)
             LEFT JOIN grants g ON g.grant_id=r.grant_id
             WHERE r.resource_key=?1",
            [hex::encode(key.0.0)],
            |row| {
                Ok(DirectPolicyRow {
                    resource_key: row.get(0)?,
                    content_id: row.get(1)?,
                    grant_id: row.get(2)?,
                    grant_epoch: row.get(3)?,
                    file_size: row.get(4)?,
                    source_relative: row.get(5)?,
                    extensions_json: row.get(6)?,
                    audience: row.get(7)?,
                    max_snapshot_bytes: row.get(8)?,
                    allow_derived_disclosure: row.get(9)?,
                    origin: row.get(10)?,
                    active: row.get(11)?,
                    label_json: row.get(12)?,
                    snapshot_state: row.get(13)?,
                    grant_status: row.get(14)?,
                    source_grant_epoch: row.get(15)?,
                    group_id: row.get(16)?,
                })
            },
        )
        .optional()
        .map_err(database_error)?;
    let Some(row) = row else {
        path.remove(key);
        return Ok(None);
    };
    let (Some(grant_text), Some(epoch_i64), Some(max_bytes_i64)) =
        (row.grant_id, row.grant_epoch, row.max_snapshot_bytes)
    else {
        path.remove(key);
        return Ok(None);
    };
    let epoch = u64::try_from(epoch_i64).map_err(|_| AslError::InvalidDatabase)?;
    let file_size = u64::try_from(row.file_size).map_err(|_| AslError::InvalidDatabase)?;
    let max_bytes = u64::try_from(max_bytes_i64).map_err(|_| AslError::InvalidDatabase)?;
    let source_epoch = row
        .source_grant_epoch
        .map(u64::try_from)
        .transpose()
        .map_err(|_| AslError::InvalidDatabase)?;
    if row.active != 1
        || row.snapshot_state != "ready"
        || row.grant_status.as_deref() != Some("active")
        || (matches!(row.origin.as_str(), "local" | "derived") && source_epoch != Some(epoch))
        || file_size > max_bytes
    {
        path.remove(key);
        return Ok(None);
    }
    let Some(extension) = row
        .source_relative
        .as_deref()
        .and_then(|path| Path::new(path).extension())
        .and_then(|extension| extension.to_str())
        .map(|extension| format!(".{}", extension.to_ascii_lowercase()))
    else {
        path.remove(key);
        return Ok(None);
    };
    let extensions: Vec<String> =
        serde_json::from_str(&row.extensions_json).map_err(|_| AslError::InvalidDatabase)?;
    let extensions = extensions
        .into_iter()
        .map(|extension| format!(".{}", extension.to_ascii_lowercase()))
        .collect::<HashSet<_>>();
    if extension.len() == 1
        || !extensions.contains(&extension)
        || !extension[1..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        path.remove(key);
        return Ok(None);
    }
    let audience = match row.audience.as_str() {
        "public" => Audience::Public,
        "contacts" => Audience::Contacts,
        "peers" => {
            let authorized: bool = db
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM grant_agents
                        WHERE grant_id=?1 AND agent_id=?2
                    )",
                    params![grant_text, agent_text(requester.agent)],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if authorized {
                Audience::Peers([requester.agent].into())
            } else {
                Audience::Peers(HashSet::new())
            }
        }
        "group" => match (group_scope, row.group_id.as_deref()) {
            (Some(group), Some(granted)) if granted == hex::encode(group.0.as_bytes()) => {
                Audience::Group(group.clone())
            }
            _ => Audience::Peers(HashSet::new()),
        },
        _ => {
            path.remove(key);
            return Err(AslError::InvalidDatabase);
        }
    };
    let label: serde_json::Value =
        serde_json::from_str(&row.label_json).map_err(|_| AslError::InvalidDatabase)?;
    let origin = match row.origin.as_str() {
        "local" => ResourceOrigin::Local,
        "remote" => ResourceOrigin::Remote {
            reuse_allowed: label
                .get("reuse_allowed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        },
        "derived" => {
            let source_texts = {
                let mut statement = db
                    .prepare(
                        "SELECT source_resource_key FROM derivation_sources
                         WHERE derived_resource_key=?1 ORDER BY source_resource_key",
                    )
                    .map_err(database_error)?;
                statement
                    .query_map([row.resource_key.clone()], |row| row.get::<_, String>(0))
                    .map_err(database_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(database_error)?
            };
            if source_texts.is_empty() || source_texts.len() > 8 {
                path.remove(key);
                return Ok(None);
            }
            let sources = source_texts
                .iter()
                .map(|source| Ok(ResourceKey(Id128(bytes(source)?))))
                .collect::<Result<Vec<_>, AslError>>()?;
            ResourceOrigin::Derived {
                sources,
                disclosure_allowed: label
                    .get("disclosure_allowed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }
        }
        _ => {
            path.remove(key);
            return Err(AslError::InvalidDatabase);
        }
    };
    let grant_id = GrantId(Id128(bytes(&grant_text)?));
    let node = PolicyNode {
        key: ResourceKey(Id128(bytes(&row.resource_key)?)),
        resource: ResourcePolicy {
            content_id: Hash32(bytes(&row.content_id)?),
            grant_id: grant_id.clone(),
            grant_epoch: epoch,
            active: true,
            snapshot_ready: true,
            file_size,
            extension,
            retention_until_ms: None,
            origin,
        },
        grant: GrantPolicy {
            epoch,
            active: true,
            audience,
            model_policy: ModelPolicy::Never,
            extensions,
            max_snapshot_bytes: max_bytes,
            allowed_operations: [
                AccessOperation::Search,
                AccessOperation::ReadMetadata,
                AccessOperation::ReadChunk,
            ]
            .into(),
            allow_derived_disclosure: row.allow_derived_disclosure != 0,
        },
        sources: Vec::new(),
    };
    let mut node = node;
    if let ResourceOrigin::Derived { sources, .. } = &node.resource.origin {
        for source in sources {
            let Some(source_node) =
                load_policy_node(db, requester, group_scope, source, depth + 1, path)?
            else {
                path.remove(key);
                return Ok(None);
            };
            node.sources.push(source_node);
        }
    }
    path.remove(key);
    Ok(Some(node))
}

pub(super) fn flatten_dependencies(
    node: &PolicyNode,
    output: &mut Vec<(ResourceKey, ResourcePolicy, GrantPolicy)>,
) {
    for source in &node.sources {
        output.push((
            source.key.clone(),
            source.resource.clone(),
            source.grant.clone(),
        ));
        flatten_dependencies(source, output);
    }
}
