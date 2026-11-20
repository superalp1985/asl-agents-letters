//! Core-only bridge from a live direct admission and durable grants to scoped search.
use std::{path::Path, time::Duration};

use asl_policy::{
    AccessOperation, Audience, AuthenticatedDevice, GrantPolicy, ModelPolicy, Permit,
    PolicyRevision, PolicySnapshot, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    task::{GrantId, ResourceKey},
};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

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
        // Retired imports have no FTS entry and must not starve current resources.
        let mut statement = tx
            .prepare_cached("SELECT rowid FROM resource_fts ORDER BY rowid DESC LIMIT ?1")
            .map_err(database_error)?;
        let rows = statement
            .query_map([MAX_KEYS as i64], |row| row.get::<_, i64>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        drop(statement);
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
            if row.grant.audience == Audience::Contacts {
                snapshot.contacts.insert(requester.agent);
            }
            keys.push(row.key.clone());
            snapshot
                .grants
                .insert(row.resource.grant_id.clone(), row.grant);
            snapshot.resources.insert(row.key, row.resource);
        })?;
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
        enqueue: impl FnOnce() -> Result<T, AslError>,
    ) -> Result<T, AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if direct_revision(&tx, requester)? != expected_revision {
            return Err(AslError::PolicyVersionConflict);
        }
        if let Some(permit) = permit {
            if permit.requester_agent_id() != Some(requester.agent)
                || permit.authenticated_device_peer_id() != Some(&requester.peer)
                || permit.operation() != AccessOperation::ReadMetadata
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
        // No writes to commit. Drop the lock immediately after queueing.
        enqueue()
    }
}

struct DirectRow {
    key: ResourceKey,
    resource: ResourcePolicy,
    grant: GrantPolicy,
}

fn direct_revision(
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
            "SELECT r.resource_key,r.content_id,r.grant_id,g.epoch,s.file_size,
                r.source_relative,g.extensions_json,g.audience,g.max_snapshot_bytes
         FROM json_each(?3) k CROSS JOIN resources r ON r.{lookup}=k.value
         {AUTHORITY} AND g.audience<>'group'"
        ))
        .map_err(database_error)?;
    let mut rows = statement
        .query(params![
            agent_text(requester.agent),
            bs58::encode(requester.peer.as_bytes()).into_string(),
            ids
        ])
        .map_err(database_error)?;
    while let Some(row) = rows.next().map_err(database_error)? {
        let relative: Option<String> = row.get(5).map_err(database_error)?;
        let Some(extension) = relative
            .as_deref()
            .and_then(|p| Path::new(p).extension())
            .and_then(|ext| ext.to_str())
            .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        else {
            continue;
        };
        let extensions: Vec<String> =
            serde_json::from_str(&row.get::<_, String>(6).map_err(database_error)?)
                .map_err(|_| AslError::InvalidDatabase)?;
        let extensions = extensions
            .into_iter()
            .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
            .collect::<std::collections::HashSet<_>>();
        if extension.len() == 1
            || !extensions.contains(&extension)
            || !extension[1..].bytes().all(|b| b.is_ascii_alphanumeric())
        {
            continue;
        }
        let audience = match row.get_ref(7).map_err(database_error)?.as_str() {
            Ok("public") => Audience::Public,
            Ok("contacts") => Audience::Contacts,
            Ok("peers") => Audience::Peers([requester.agent].into()),
            _ => return Err(AslError::InvalidDatabase),
        };
        let unsigned = |index| {
            u64::try_from(row.get::<_, i64>(index).map_err(database_error)?)
                .map_err(|_| AslError::InvalidDatabase)
        };
        let epoch = unsigned(3)?;
        visit(DirectRow {
            key: ResourceKey(Id128(bytes(
                &row.get::<_, String>(0).map_err(database_error)?,
            )?)),
            resource: ResourcePolicy {
                content_id: Hash32(bytes(&row.get::<_, String>(1).map_err(database_error)?)?),
                grant_id: GrantId(Id128(bytes(
                    &row.get::<_, String>(2).map_err(database_error)?,
                )?)),
                grant_epoch: epoch,
                active: true,
                snapshot_ready: true,
                file_size: unsigned(4)?,
                extension,
                retention_until_ms: None,
                origin: ResourceOrigin::Local,
            },
            grant: GrantPolicy {
                epoch,
                active: true,
                audience,
                model_policy: ModelPolicy::Never,
                extensions,
                max_snapshot_bytes: unsigned(8)?,
                allowed_operations: [AccessOperation::Search, AccessOperation::ReadMetadata].into(),
                allow_derived_disclosure: false,
            },
        });
    }
    Ok(())
}
