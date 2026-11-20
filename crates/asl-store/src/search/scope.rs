use asl_policy::{AccessOperation, AccessRequest, Permit, PolicyService, Principal};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    task::{GrantId, ResourceKey},
};
use rusqlite::{Connection, OptionalExtension, params};

use super::{MAX_KEYS, ResourceSearch};
use crate::{chain::agent_text, current_time_ms, database_error};

pub(super) enum Selection<'a> {
    All,
    Keys(&'a [ResourceKey]),
    Page(&'a [i64]),
}

pub(super) struct Allowed {
    pub row: i64,
    pub key: ResourceKey,
    pub search: Permit,
}

pub(super) fn bytes<const N: usize>(hex_text: &str) -> Result<[u8; N], AslError> {
    let mut bytes = [0; N];
    hex::decode_to_slice(hex_text, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(bytes)
}

// Only identifiers and authority fields here, never document text or MATCH.
const FIELDS: &str = "SELECT r.row_id,r.resource_key,r.grant_id,r.content_id,g.epoch,g.group_id,grp.membership_epoch";
pub(super) const AUTHORITY: &str = "CROSS JOIN grants g ON g.grant_id=r.grant_id
    CROSS JOIN snapshots s ON s.content_id=r.content_id
    LEFT JOIN asl_groups grp ON grp.group_id=g.group_id
    WHERE r.origin='local' AND r.active=1 AND s.state='ready' AND g.status='active'
    AND r.source_grant_epoch=g.epoch AND s.file_size<=g.max_snapshot_bytes
    AND (g.audience='public'
      OR (g.audience='contacts' AND EXISTS(SELECT 1 FROM authorized_contacts WHERE agent_id=?1))
      OR (g.audience='peers' AND EXISTS(SELECT 1 FROM grant_agents ga WHERE ga.grant_id=g.grant_id AND ga.agent_id=?1))
      OR (g.audience='group' AND grp.state='active' AND EXISTS(SELECT 1 FROM group_members m
          WHERE m.group_id=g.group_id AND m.peer_id=?2 AND m.state='active')))";

/// Read only primary keys, before either SQL or policy can discard any rows.
/// The extra row is the inclusive start of the next page; no rowid arithmetic.
pub(super) fn physical_page(
    db: &Connection,
    first: i64,
    budget: u32,
) -> Result<(Vec<i64>, Option<i64>), AslError> {
    if budget == 0 || budget as usize > MAX_KEYS {
        return Err(AslError::QuotaExceeded);
    }
    let mut stmt = db
        .prepare_cached("SELECT row_id FROM resources WHERE row_id>=?1 ORDER BY row_id LIMIT ?2")
        .map_err(database_error)?;
    let mut ids = stmt
        .query_map(params![first, budget + 1], |row| row.get(0))
        .map_err(database_error)?
        .collect::<Result<Vec<i64>, _>>()
        .map_err(database_error)?;
    let next = if ids.len() > budget as usize {
        ids.pop()
    } else {
        None
    };
    Ok((ids, next))
}

impl ResourceSearch<'_> {
    pub(super) fn visit_allowed(
        &self,
        db: &Connection,
        revision: u64,
        selection: Selection<'_>,
        mut visit: impl FnMut(Allowed) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let peer = self.policy.device_peer_id().ok_or(AslError::NotFound)?;
        let peer = bs58::encode(peer.as_bytes()).into_string();
        let agent = agent_text(self.agent);
        let (lookup, order, ids) = match selection {
            Selection::All => {
                let (rows, next) = physical_page(db, i64::MIN, MAX_KEYS as u32)?;
                if next.is_some() {
                    return Err(AslError::QuotaExceeded);
                }
                ("row_id", "resource_key", serde_json::to_string(&rows))
            }
            Selection::Page(rows) => ("row_id", "row_id", serde_json::to_string(rows)),
            Selection::Keys(keys) => (
                "resource_key",
                "resource_key",
                serde_json::to_string(&keys.iter().map(|k| hex::encode(k.0.0)).collect::<Vec<_>>()),
            ),
        };
        let ids = ids.map_err(|_| AslError::InvalidPolicyState)?;
        // Drive PK/unique-index lookups from the bounded input, not from the grants table.
        let mut stmt = db
            .prepare_cached(&format!(
                "{FIELDS} FROM (SELECT DISTINCT value FROM json_each(?3)) k
                CROSS JOIN resources r ON r.{lookup}=k.value {AUTHORITY} ORDER BY r.{order}"
            ))
            .map_err(database_error)?;
        let mut rows = stmt
            .query(params![agent, peer, ids])
            .map_err(database_error)?;
        while let Some(r) = rows.next().map_err(database_error)? {
            let key = ResourceKey(Id128(bytes(
                &r.get::<_, String>(1).map_err(database_error)?,
            )?));
            let grant = GrantId(Id128(bytes(
                &r.get::<_, String>(2).map_err(database_error)?,
            )?));
            let content = Hash32(bytes(&r.get::<_, String>(3).map_err(database_error)?)?);
            let epoch = u64::try_from(r.get::<_, i64>(4).map_err(database_error)?)
                .map_err(|_| AslError::InvalidDatabase)?;
            let group: Option<String> = r.get(5).map_err(database_error)?;
            let membership = r
                .get::<_, Option<i64>>(6)
                .map_err(database_error)?
                .map(u64::try_from)
                .transpose()
                .map_err(|_| AslError::InvalidDatabase)?;
            let Some(search) = self.permit(&key, grant, AccessOperation::Search, revision)? else {
                continue;
            };
            if search.content_id() != content || search.grant_epoch() != epoch {
                continue;
            }
            let group_allowed = match (group, search.group_binding()) {
                (Some(group), Some((id, epoch))) => {
                    hex::encode(id.0.0) == group && Some(epoch) == membership
                }
                (Some(_), None) => false,
                (None, None) => true,
                // The request can be group-scoped even if the durable grant isn't.
                (None, Some((id, epoch))) => {
                    let live: Option<i64> = db.prepare_cached("SELECT g.membership_epoch FROM asl_groups g
                        CROSS JOIN group_members m ON m.group_id=g.group_id
                        WHERE g.group_id=?1 AND g.state='active' AND m.peer_id=?2 AND m.state='active'")
                        .map_err(database_error)?.query_row(params![hex::encode(id.0.0), peer], |r| r.get(0))
                        .optional().map_err(database_error)?;
                    live.and_then(|e| u64::try_from(e).ok()) == Some(epoch)
                }
            };
            if !group_allowed {
                continue;
            }
            visit(Allowed {
                row: r.get(0).map_err(database_error)?,
                key,
                search,
            })?;
        }
        Ok(())
    }

    fn permit(
        &self,
        key: &ResourceKey,
        grant: GrantId,
        operation: AccessOperation,
        revision: u64,
    ) -> Result<Option<Permit>, AslError> {
        let request = AccessRequest {
            resource_key: key.clone(),
            grant_id: grant,
            principal: Principal::Agent(self.agent),
            operation,
        };
        match self.policy.authorize(&request, current_time_ms() as u64) {
            Ok(p) if p.policy_revision().0 == revision => Ok(Some(p)),
            Ok(_) => Err(AslError::PolicyVersionConflict),
            Err(AslError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(super) fn metadata_permit(
        &self,
        allowed: &Allowed,
        revision: u64,
    ) -> Result<Option<Permit>, AslError> {
        Ok(self
            .permit(
                &allowed.key,
                allowed.search.grant_id().clone(),
                AccessOperation::ReadMetadata,
                revision,
            )?
            .filter(|p| {
                p.content_id() == allowed.search.content_id()
                    && p.grant_epoch() == allowed.search.grant_epoch()
            }))
    }
}
