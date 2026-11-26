//! Group-scoped resource search and final disclosure checks.
//!
//! The group id and membership epoch are local broker facts. They are never
//! accepted from a group application or from a model.

use std::collections::HashSet;

use asl_policy::{
    AccessOperation, GroupPolicy, Permit, PolicyRevision, PolicySnapshot, ResourcePolicy,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    task::{GroupId, ResourceKey},
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    MAX_KEYS,
    direct::{DirectRequester, direct_revision, flatten_dependencies, load_policy_node},
    scope::{AUTHORITY, bytes},
};
use crate::{
    Store, chain::agent_text, conversation::scoped_group_id, current_time_ms, database_error,
};

/// A peer authenticated inside one exact local group epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRequester {
    pub direct: DirectRequester,
    pub wire_id: Hash32,
    pub group_id: GroupId,
    pub membership_epoch: u64,
}

impl Store {
    /// Reconstructs the current local group capability from already-verified
    /// MLS membership and cached chain/device evidence. Use only after the MLS
    /// sender leaf has been authenticated for this exact room and epoch.
    pub fn cached_group_requester(
        &self,
        wire_id: Hash32,
        agent: AgentId,
        peer: &PeerId,
        now_ms: u64,
    ) -> Result<Option<GroupRequester>, AslError> {
        let Some(snapshot) = self.mls_room_snapshot(wire_id)? else {
            return Ok(None);
        };
        if self
            .mls_room_progress(wire_id)?
            .is_none_or(|(state, _)| state != "active")
        {
            return Ok(None);
        }
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let agent_text = agent_text(agent);
        let peer_text = peer_text(peer);
        let row = self
            .connection
            .query_row(
                "SELECT r.sequence,r.controller_address,r.state_commitment,
                        d.certificate_expires_ms
                 FROM identity_registry_states r
                 JOIN device_identities d ON d.agent_id=r.agent_id
                 JOIN agents a ON a.agent_id=r.agent_id
                 WHERE r.agent_id=?1 AND r.status='active'
                   AND d.peer_id=?2 AND d.revoked_at_ms IS NULL
                   AND d.certificate_expires_ms>?3
                   AND a.identity_state IN ('pending_anchor','verified')",
                params![agent_text, peer_text, now],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((sequence, controller, commitment, certificate_expires)) = row else {
            return Ok(None);
        };
        let session_expires_at_ms = u64::try_from(certificate_expires)
            .map_err(|_| AslError::InvalidDatabase)?
            .min(now_ms.saturating_add(60_000));
        Ok(Some(GroupRequester {
            direct: DirectRequester {
                agent,
                peer: peer.clone(),
                session_expires_at_ms,
                registry_sequence: u64::try_from(sequence)
                    .map_err(|_| AslError::InvalidDatabase)?,
                directory_commitment: commitment
                    .try_into()
                    .map_err(|_| AslError::InvalidDatabase)?,
                controller: controller
                    .try_into()
                    .map_err(|_| AslError::InvalidDatabase)?,
            },
            wire_id,
            group_id: snapshot.local_id,
            membership_epoch: snapshot.version.membership_epoch,
        }))
    }

    pub fn group_search_snapshot(
        &self,
        requester: &GroupRequester,
    ) -> Result<(PolicySnapshot, Vec<ResourceKey>), AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let revision = group_revision(&tx, requester)?;
        let group_text = hex::encode(requester.group_id.0.as_bytes());
        let mut statement = tx
            .prepare_cached(&format!(
                "SELECT f.rowid FROM resource_fts f
                 CROSS JOIN resources r ON r.row_id=f.rowid AND r.resource_key=f.resource_key
                 {AUTHORITY} AND (g.audience<>'group' OR g.group_id=?3)
                 ORDER BY f.rowid DESC LIMIT ?4"
            ))
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    agent_text(requester.direct.agent),
                    peer_text(&requester.direct.peer),
                    group_text.clone(),
                    MAX_KEYS as i64 + 1,
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
        snapshot.devices.insert(
            requester.direct.peer.clone(),
            asl_policy::AuthenticatedDevice {
                agent_id: requester.direct.agent,
                active: true,
                chain_valid_until_ms: requester.direct.session_expires_at_ms,
                certificate_valid_until_ms: requester.direct.session_expires_at_ms,
            },
        );
        snapshot.groups.insert(
            requester.group_id.clone(),
            GroupPolicy {
                active: true,
                membership_epoch: requester.membership_epoch,
                members: HashSet::from([requester.direct.peer.clone()]),
            },
        );
        let mut keys = Vec::new();
        visit_group_rows(&tx, requester, "row_id", &ids, |row| {
            keys.push(row.key.clone());
            snapshot
                .grants
                .insert(row.resource.grant_id.clone(), row.grant);
            snapshot.resources.insert(row.key, row.resource);
            for (key, resource, grant) in row.dependencies {
                snapshot.grants.insert(resource.grant_id.clone(), grant);
                snapshot.resources.insert(key, resource);
            }
            Ok(())
        })?;
        if contact(&tx, requester.direct.agent)? {
            snapshot.contacts.insert(requester.direct.agent);
        }
        tx.commit().map_err(database_error)?;
        Ok((snapshot, keys))
    }

    /// Recheck the exact group epoch and resource permit immediately before
    /// the group reply leaves the local Core.
    pub fn with_current_group_authority<T>(
        &self,
        requester: &GroupRequester,
        expected_revision: PolicyRevision,
        permit: Option<&Permit>,
        root_task_id: Option<Id128>,
        action: impl FnOnce() -> Result<T, AslError>,
    ) -> Result<T, AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(|error| match error.sqlite_error_code() {
                Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
                    AslError::PolicyVersionConflict
                }
                _ => database_error(error),
            })?;
        if group_revision(&tx, requester)? != expected_revision {
            return Err(AslError::PolicyVersionConflict);
        }
        if let Some(permit) = permit {
            if permit.requester_agent_id() != Some(requester.direct.agent)
                || permit.authenticated_device_peer_id() != Some(&requester.direct.peer)
                || !matches!(
                    permit.operation(),
                    AccessOperation::ReadMetadata | AccessOperation::ReadChunk
                )
                || permit.group_binding()
                    != Some((requester.group_id.clone(), requester.membership_epoch))
                || permit.policy_revision() != expected_revision
                || permit.expires_at_ms() <= current_time_ms() as u64
            {
                return Err(AslError::NotFound);
            }
            let ids = serde_json::to_string(&[hex::encode(permit.resource_key().0.0)])
                .map_err(|_| AslError::InvalidPolicyState)?;
            let mut allowed = false;
            visit_group_rows(&tx, requester, "resource_key", &ids, |row| {
                allowed = &row.resource.grant_id == permit.grant_id()
                    && row.resource.grant_epoch == permit.grant_epoch()
                    && row.resource.content_id == permit.content_id()
                    && row.resource.file_size == permit.file_size();
                Ok(())
            })?;
            if !allowed {
                return Err(AslError::NotFound);
            }
        }
        if let Some(root_task_id) = root_task_id {
            let root = scoped_group_id(b"root", requester.wire_id, root_task_id);
            let updated = tx
                .execute(
                    "UPDATE direct_inbound_conversations SET messages_used=messages_used+1
                     WHERE agent_id=?1 AND root_task_id=?2 AND expires_at_ms>?3
                       AND rounds_used<=3 AND messages_used<6",
                    params![
                        agent_text(requester.direct.agent),
                        hex::encode(root.0),
                        current_time_ms()
                    ],
                )
                .map_err(database_error)?;
            if updated != 1 {
                return Err(AslError::QuotaExceeded);
            }
        }
        tx.commit().map_err(database_error)?;
        action()
    }
}

struct GroupRow {
    key: ResourceKey,
    resource: ResourcePolicy,
    grant: asl_policy::GrantPolicy,
    dependencies: Vec<(ResourceKey, ResourcePolicy, asl_policy::GrantPolicy)>,
}

fn group_revision(
    db: &rusqlite::Connection,
    requester: &GroupRequester,
) -> Result<PolicyRevision, AslError> {
    let revision = direct_revision(db, &requester.direct)?;
    let active: bool = db
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM asl_groups g JOIN group_members m ON m.group_id=g.group_id
                WHERE g.group_id=?1 AND g.state='active'
                  AND g.membership_epoch=?2 AND m.peer_id=?3 AND m.state='active'
             )",
            params![
                hex::encode(requester.group_id.0.as_bytes()),
                sql_number(requester.membership_epoch)?,
                peer_text(&requester.direct.peer)
            ],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !active {
        return Err(AslError::NotFound);
    }
    Ok(revision)
}

fn visit_group_rows(
    db: &rusqlite::Connection,
    requester: &GroupRequester,
    lookup: &'static str,
    ids: &str,
    mut visit: impl FnMut(GroupRow) -> Result<(), AslError>,
) -> Result<(), AslError> {
    let mut statement = db
        .prepare_cached(&format!(
            "SELECT r.resource_key FROM json_each(?3) k
             CROSS JOIN resources r ON r.{lookup}=k.value
             {AUTHORITY} AND (g.audience<>'group' OR g.group_id=?4)"
        ))
        .map_err(database_error)?;
    let keys = statement
        .query_map(
            params![
                agent_text(requester.direct.agent),
                peer_text(&requester.direct.peer),
                ids,
                hex::encode(requester.group_id.0.as_bytes())
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    drop(statement);
    for key in keys {
        let key = ResourceKey(Id128(bytes(&key)?));
        let Some(node) = load_policy_node(
            db,
            &requester.direct,
            Some(&requester.group_id),
            &key,
            0,
            &mut HashSet::new(),
        )?
        else {
            continue;
        };
        let mut dependencies = Vec::new();
        flatten_dependencies(&node, &mut dependencies);
        visit(GroupRow {
            key: node.key,
            resource: node.resource,
            grant: node.grant,
            dependencies,
        })?;
    }
    Ok(())
}

fn contact(db: &rusqlite::Connection, agent: AgentId) -> Result<bool, AslError> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM authorized_contacts WHERE agent_id=?1)",
        [agent_text(agent)],
        |row| row.get(0),
    )
    .map_err(database_error)
}

fn peer_text(peer: &PeerId) -> String {
    bs58::encode(peer.as_bytes()).into_string()
}

fn sql_number(value: u64) -> Result<i64, AslError> {
    i64::try_from(value).map_err(|_| AslError::InvalidPolicyState)
}
