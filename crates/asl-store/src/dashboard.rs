//! A bounded, local observation snapshot. None of these rows grant permission.
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

use asl_types::{
    error::AslError,
    ids::{AgentId, Id128},
    record::short_code,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, Transaction};
use serde::{Deserialize, Serialize};

use crate::group_observations::group_observation_days;
use crate::group_state::GroupInboundPolicy;
use crate::inbound_observations::{
    DirectInboundObservation, direct_observation_days, read_recent_direct_inbound_observations,
};
use crate::network_privacy::{
    NetworkReport, force_relay_only, last_network_report, network_pause_requested,
};
use crate::public_profile::{ProfileSigningStatus, profile_signing_status};
pub use crate::remote_profiles::RemoteProfileRow;
use crate::remote_profiles::read_remote_profiles;
use crate::transfers::{DownloadConsent, UploadConsent};
use crate::{SCHEMA_VERSION, Store, current_time_ms, database_error, read_setting};

const LOCAL_IDENTITY_SETTING: &str = "ui.local_identity.v1";

#[derive(Default)]
pub struct Dashboard {
    pub identity: LocalIdentity,
    pub activity: Vec<ActivityRow>,
    pub direct_observations: Vec<DirectInboundObservation>,
    pub direct_observation_days: u8,
    pub group_observation_days: u8,
    pub force_relay_only: bool,
    pub network_pause_requested: bool,
    pub network_report: Option<NetworkReport>,
    pub profile_signing: ProfileSigningStatus,
    pub nodes: Vec<NodeRow>,
    pub remote_profiles: Vec<RemoteProfileRow>,
    pub profile_lookup: Option<crate::profile_lookup::ProfileLookup>,
    pub contact_bindings: Vec<ContactBindingRow>,
    pub binding_candidates: Vec<BindingCandidateRow>,
    pub binding_actions: Vec<BindingActionRow>,
    pub binding_code_public: bool,
    pub contact_invites: Vec<crate::contact_invites::ContactInvite>,
    pub contact_invite_prompts: Vec<crate::contact_invites::ContactInvitePrompt>,
    pub groups: Vec<GroupRow>,
    pub group_rejoin_hints: Vec<GroupRejoinHint>,
    pub group_invitations: Vec<crate::group_state::invite_review::ReviewedInvite>,
    pub group_admin_snapshot: Option<crate::group_state::operator::AdminSnapshot>,
    pub group_admin_status: Option<crate::group_state::operator::AdminOutcome>,
    pub group_decision: Option<crate::group_state::invite_review::Decision>,
    pub group_inbound: GroupInboundPolicy,
    pub group_inbound_unset: bool,
    pub transfers: Vec<TransferRow>,
    pub direct_inbound_mode: String,
    pub direct_inbound_unset: bool,
    pub download_mode: String,
    pub upload_mode: String,
    pub download_approvals: Vec<DownloadConsent>,
    pub host_inbox_request: Option<Id128>,
    pub upload_approvals: Vec<UploadConsent>,
    pub knowledge: Vec<KnowledgeRow>,
    pub trust: Vec<TrustRow>,
    pub access: Vec<AccessRow>,
}

#[derive(Default)]
pub struct LocalIdentity {
    pub agent_id: Option<String>,
    pub binding_code: Option<String>,
    pub identity_state: Option<String>,
    pub chain_state: Option<String>,
    pub network_state: Option<String>,
    pub finalized_height: Option<u64>,
    pub peer_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct LocalIdentityProjection {
    pub agent_id: String,
    pub peer_id: String,
    pub network_state: String,
    #[serde(default)]
    pub binding_code: String,
}

#[derive(serde::Serialize)]
pub struct ContactBindingRow {
    pub agent_id: String,
    pub authorized: bool,
    pub peer_id: Option<String>,
    pub state: String,
    pub updated_at_ms: i64,
}

pub struct BindingCandidateRow {
    pub agent_id: String,
    pub peer_id: String,
    pub code: String,
    pub first_seen_ms: i64,
    pub dismissed: bool,
}

pub struct BindingActionRow {
    pub kind: String,
    pub code: Option<String>,
    pub state: String,
    pub result: Option<String>,
    pub requested_at_ms: i64,
}

impl Store {
    pub fn set_local_identity_projection(
        &self,
        projection: &LocalIdentityProjection,
    ) -> Result<(), AslError> {
        let value = serde_json::to_string(projection).map_err(|_| AslError::InvalidDatabase)?;
        self.set_setting(LOCAL_IDENTITY_SETTING, &value, current_time_ms())
    }
}

pub struct ActivityRow {
    pub created_at_ms: i64,
    pub scope: String,
    pub context_id: String,
    pub direction: Option<String>,
    pub kind: String,
    pub peer_id: String,
    pub agent_id: Option<String>,
    pub preview: Option<String>,
}

pub struct NodeRow {
    pub peer_id: String,
    pub agent_id: String,
    pub identity_state: String,
    pub last_seen_ms: i64,
}

pub struct GroupRow {
    pub group_id: String,
    pub name: String,
    pub state: String,
    pub mls_epoch: u64,
    pub membership_epoch: u64,
    pub active_members: u64,
}

pub struct GroupRejoinHint {
    pub group_id: String,
    pub name: String,
    pub owner_agent_id: String,
    pub last_epoch: u64,
}

pub struct TransferRow {
    pub transfer_id: String,
    pub content_id: String,
    pub state: String,
    pub durable_bytes: u64,
    pub file_size: u64,
    pub source_count: u64,
    pub updated_at_ms: i64,
}

pub struct KnowledgeRow {
    pub title: String,
    pub origin: String,
    pub evidence_status: String,
    pub active: bool,
    pub updated_at_ms: i64,
}

pub struct TrustRow {
    pub agent_id: String,
    pub integrity: [u64; 2],
    pub availability: [u64; 2],
    pub evidence: [u64; 2],
    pub promise: [u64; 2],
    pub contributions: u64,
    pub preferred: bool,
}

pub struct AccessRow {
    pub indexed_files: u64,
    pub kind: String,
    pub id: String,
    pub directory: String,
    pub directory_path: String,
    pub scope: String,
    pub state: String,
    pub epoch: u64,
    pub extensions: String,
    pub max_bytes: u64,
    pub model_policy: String,
    pub allow_derived_disclosure: bool,
}

impl Dashboard {
    pub fn load(database: &Path) -> Result<Self, AslError> {
        let mut connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(database_error)?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(database_error)?;
        let tx = connection.transaction().map_err(database_error)?;
        let version: i64 = tx
            .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .map_err(database_error)?;
        if version != SCHEMA_VERSION {
            return Err(AslError::UnsupportedSchemaVersion);
        }
        let mut dashboard = Self::read(&tx)?;
        tx.commit().map_err(database_error)?;
        // Reuse the transfer layer's eligibility filters through this read-only connection.
        let store = Store { connection };
        dashboard.download_mode = match store.download_mode()? {
            crate::transfers::DownloadMode::Ask => "ask",
            crate::transfers::DownloadMode::Automatic => "automatic",
        }
        .into();
        dashboard.upload_mode = match store.upload_mode()? {
            crate::transfers::UploadMode::Ask => "ask",
            crate::transfers::UploadMode::Automatic => "automatic",
        }
        .into();
        dashboard.download_approvals = store.download_consents()?;
        dashboard.upload_approvals = store.upload_consents()?;
        Ok(dashboard)
    }

    fn read(database: &Transaction<'_>) -> Result<Self, AslError> {
        let direct_inbound = read_setting(database, "agent.direct_inbound_mode_v1")?;
        let group_inbound = GroupInboundPolicy::read_saved(database)?;
        let identity = read_identity(database)?;
        let now = current_time_ms() as u64;
        let local = identity
            .agent_id
            .as_deref()
            .and_then(|s| bs58::decode(s).into_vec().ok()?.try_into().ok())
            .map(AgentId);
        let device = identity.peer_id.as_deref().and_then(|s| {
            asl_types::ids::PeerId::from_bytes(bs58::decode(s).into_vec().ok()?).ok()
        });
        let (group_admin_snapshot, group_admin_status) =
            crate::group_state::operator::projection(database, local.zip(device.as_ref()), now)?;
        let group_invitations = match (local, device) {
            (Some(a), Some(p)) => crate::group_state::invite_review::list(database, a, &p, now)?,
            _ => Vec::new(),
        };
        let now_i64 = i64::try_from(now).map_err(|_| AslError::InvalidMessage)?;
        Ok(Self {
            identity,
            group_admin_snapshot,
            group_admin_status,
            group_invitations,
            group_decision: crate::group_state::invite_review::status(database, now)?,
            activity: read_activity(database)?,
            direct_observations: read_recent_direct_inbound_observations(database)?,
            direct_observation_days: direct_observation_days(database)?,
            group_observation_days: group_observation_days(database)?,
            force_relay_only: force_relay_only(database)?,
            network_pause_requested: network_pause_requested(database)?,
            network_report: last_network_report(database)?,
            profile_signing: profile_signing_status(database)?,
            nodes: read_nodes(database)?,
            remote_profiles: read_remote_profiles(database, current_time_ms())?,
            profile_lookup: crate::profile_lookup::status(database, current_time_ms())?,
            contact_bindings: read_contact_bindings(database)?,
            binding_candidates: read_binding_candidates(database)?,
            binding_actions: read_binding_actions(database)?,
            binding_code_public: read_binding_code_public(database)?,
            contact_invites: crate::contact_invites::active_invites_for_dashboard(
                database, now_i64,
            )?,
            contact_invite_prompts: crate::contact_invites::prompts_for_dashboard(
                database, now_i64,
            )?,
            groups: read_groups(database)?,
            group_rejoin_hints: read_group_rejoin_hints(database)?,
            group_inbound: group_inbound.unwrap_or_default(),
            group_inbound_unset: group_inbound.is_none(),
            transfers: read_transfers(database)?,
            direct_inbound_mode: match direct_inbound.as_deref() {
                Some("\"browse_only\"") => "browse",
                Some("\"answer\"") => "answer",
                _ => "off",
            }
            .into(),
            direct_inbound_unset: direct_inbound.is_none(),
            download_mode: String::new(),
            upload_mode: String::new(),
            download_approvals: Vec::new(),
            host_inbox_request: crate::host_inbox::pending_request(
                database,
                current_time_ms() as u64,
            )?,
            upload_approvals: Vec::new(),
            knowledge: read_knowledge(database)?,
            trust: read_trust(database)?,
            access: read_access(database)?,
        })
    }
}

pub(crate) fn read_identity(database: &Connection) -> Result<LocalIdentity, AslError> {
    let projection = database
        .query_row(
            "SELECT value_json FROM settings WHERE key=?1",
            [LOCAL_IDENTITY_SETTING],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|value| {
            serde_json::from_str::<LocalIdentityProjection>(&value)
                .map_err(|_| AslError::InvalidDatabase)
        })
        .transpose()?;
    let local = database
        .query_row(
            "SELECT i.agent_id,a.identity_state,r.status,c.finalized_height
             FROM local_agent_identity i
             JOIN agents a ON a.agent_id=i.agent_id
             LEFT JOIN identity_registry_states r ON r.agent_id=i.agent_id
             LEFT JOIN chain_state_cache c ON c.chain_id=r.chain_id
             WHERE i.singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?
                        .map(|value| unsigned(3, value))
                        .transpose()?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let (agent_id, identity_state, chain_state, finalized_height) = if let Some(projection) =
        &projection
    {
        let matching_local = local.filter(|local| local.0 == projection.agent_id);
        let (identity_state, chain_state, finalized_height) = match matching_local {
            Some((_, identity, chain, height)) => (Some(identity), chain, height),
            None => (
                match projection.network_state.as_str() {
                    "network_active" => Some("verified".to_owned()),
                    "registry_anchor_missing" => Some("pending_anchor".to_owned()),
                    _ => None,
                },
                None,
                None,
            ),
        };
        (
            Some(projection.agent_id.clone()),
            identity_state,
            chain_state,
            finalized_height,
        )
    } else {
        match local {
            Some((agent, identity, chain, height)) => (Some(agent), Some(identity), chain, height),
            None => (None, None, None, None),
        }
    };
    let peer_id = match &projection {
        Some(local) => Some(local.peer_id.clone()),
        None => database
            .query_row(
                "SELECT peer_id FROM local_device_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?,
    };
    let binding_code = projection
        .as_ref()
        .and_then(|projection| {
            (!projection.binding_code.is_empty()).then(|| projection.binding_code.clone())
        })
        .or_else(|| agent_id.as_deref().and_then(derive_binding_code));
    Ok(LocalIdentity {
        agent_id,
        binding_code,
        identity_state,
        chain_state,
        network_state: projection.map(|local| local.network_state),
        finalized_height,
        peer_id,
    })
}

fn derive_binding_code(agent_id: &str) -> Option<String> {
    let bytes = bs58::decode(agent_id).into_vec().ok()?;
    let agent_id = AgentId(bytes.try_into().ok()?);
    Some(format!("{:016}", short_code(agent_id)))
}

impl crate::Store {
    pub fn recent_contact_bindings(&self) -> Result<Vec<ContactBindingRow>, AslError> {
        read_contact_bindings(&self.connection)
    }
}

fn read_contact_bindings(database: &Connection) -> Result<Vec<ContactBindingRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT agent_id,peer_id,state,updated_at_ms
             FROM contact_bindings ORDER BY updated_at_ms DESC,agent_id LIMIT 200",
        )
        .map_err(database_error)?;
    let mut membership = database
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM authorized_contacts WHERE agent_id=?1)")
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            let agent: Vec<u8> = row.get(0)?;
            let agent_id = bs58::encode(agent).into_string();
            Ok(ContactBindingRow {
                authorized: membership.query_row([&agent_id], |r| r.get(0))?,
                agent_id,
                peer_id: row.get(1)?,
                state: row.get(2)?,
                updated_at_ms: row.get(3)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_binding_actions(database: &Connection) -> Result<Vec<BindingActionRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT kind,code,state,result,requested_at_ms FROM contact_binding_actions
         ORDER BY action_id DESC LIMIT 12",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(BindingActionRow {
                kind: row.get(0)?,
                code: row
                    .get::<_, Option<i64>>(1)?
                    .map(|value| format!("{value:016}")),
                state: row.get(2)?,
                result: row.get(3)?,
                requested_at_ms: row.get(4)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<_, _>>()
        .map_err(database_error)
}

fn read_binding_candidates(database: &Connection) -> Result<Vec<BindingCandidateRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT agent_id,peer_id,code,first_seen_ms,state
             FROM contact_binding_candidates
             ORDER BY state,first_seen_ms DESC,agent_id,peer_id LIMIT 200",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            let agent: Vec<u8> = row.get(0)?;
            let code: i64 = row.get(2)?;
            Ok(BindingCandidateRow {
                agent_id: bs58::encode(agent).into_string(),
                peer_id: row.get(1)?,
                code: format!("{code:016}"),
                first_seen_ms: row.get(3)?,
                dismissed: row.get::<_, String>(4)? == "dismissed",
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_binding_code_public(database: &Connection) -> Result<bool, AslError> {
    let value = database
        .query_row(
            "SELECT value_json FROM settings WHERE key='ui.binding_code_public.v1'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?;
    match value.as_deref() {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn read_activity(database: &Connection) -> Result<Vec<ActivityRow>, AslError> {
    let now = current_time_ms();
    let mut statement = database
        .prepare(
            "SELECT created_at_ms,scope,kind,peer_id,agent_id,context_id,direction FROM (
                 SELECT m.created_at_ms,'direct' AS scope,m.kind,p.peer_id,p.agent_id,
                        m.task_id AS context_id,m.direction,m.message_id AS event_id
                 FROM messages m JOIN peers p ON p.peer_id=m.peer_id
                 WHERE m.expires_at_ms>?1
                 UNION ALL
                 SELECT g.created_at_ms,'group',coalesce(g.browse_kind,g.kind),g.sender_peer_id,p.agent_id,
                        g.group_id,CASE WHEN g.browse_kind IS NOT NULL THEN 'in' END,g.event_id
                 FROM group_events g JOIN peers p ON p.peer_id=g.sender_peer_id
                 WHERE g.expires_at_ms>?1 AND (g.kind<>'application' OR g.browse_expires_at_ms>?1)
             ) ORDER BY created_at_ms DESC,scope,event_id LIMIT 100",
        )
        .map_err(database_error)?;
    let mut rows = statement
        .query_map([now], |row| {
            Ok(ActivityRow {
                created_at_ms: row.get(0)?,
                scope: row.get(1)?,
                kind: row.get(2)?,
                peer_id: row.get(3)?,
                agent_id: row.get(4)?,
                context_id: row.get(5)?,
                direction: row.get(6)?,
                preview: None,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    drop(statement);

    let mut history = database
        .prepare(
            "SELECT a.received_at_ms,a.direction,a.conversation_id,
                    coalesce(g.sender_peer_id,''),p.agent_id,a.ciphertext
             FROM conversation_act_events a
             LEFT JOIN group_events g
               ON g.group_id=a.conversation_id AND g.created_at_ms=a.received_at_ms
             LEFT JOIN peers p ON p.peer_id=g.sender_peer_id
             WHERE a.expires_at_ms>?1
             ORDER BY a.received_at_ms DESC,a.conversation_id,a.act_id
             LIMIT 100",
        )
        .map_err(database_error)?;
    let history_rows = history
        .query_map([now], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    drop(history);

    let mut previews = HashMap::new();
    let existing = rows
        .iter()
        .filter_map(|row| {
            row.direction
                .as_ref()
                .map(|direction| (row.created_at_ms, row.context_id.clone(), direction.clone()))
        })
        .collect::<HashSet<_>>();
    for (created, direction, conversation, peer, agent, body) in history_rows {
        let preview = crate::act_history::decode_stored_body(&body)?;
        if direction == "in" {
            previews.insert(
                (created, conversation.clone(), direction.clone()),
                preview.clone(),
            );
        }
        if !existing.contains(&(created, conversation.clone(), direction.clone())) {
            rows.push(ActivityRow {
                created_at_ms: created,
                scope: "group".into(),
                context_id: conversation,
                direction: Some(direction),
                kind: "act".into(),
                peer_id: peer,
                agent_id: agent,
                preview,
            });
        }
    }
    for row in &mut rows {
        if row.scope == "group" && row.direction.as_deref() == Some("in") {
            row.preview = previews
                .remove(&(row.created_at_ms, row.context_id.clone(), "in".into()))
                .flatten();
        }
    }
    rows.sort_by(|left, right| {
        right
            .created_at_ms
            .cmp(&left.created_at_ms)
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.context_id.cmp(&right.context_id))
            .then_with(|| left.peer_id.cmp(&right.peer_id))
    });
    rows.truncate(100);
    Ok(rows)
}

fn read_nodes(database: &Connection) -> Result<Vec<NodeRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT p.peer_id,p.agent_id,a.identity_state,p.last_seen_ms
             FROM peers p JOIN agents a ON a.agent_id=p.agent_id
             ORDER BY p.last_seen_ms DESC,p.peer_id LIMIT 200",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(NodeRow {
                peer_id: row.get(0)?,
                agent_id: row.get(1)?,
                identity_state: row.get(2)?,
                last_seen_ms: row.get(3)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_groups(database: &Connection) -> Result<Vec<GroupRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT g.group_id,g.local_name,g.state,g.mls_epoch,g.membership_epoch,
                    (SELECT COUNT(*) FROM group_members m
                     WHERE m.group_id=g.group_id AND m.state='active')
             FROM asl_groups g ORDER BY g.updated_at_ms DESC,g.group_id LIMIT 100",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(GroupRow {
                group_id: row.get(0)?,
                name: row.get(1)?,
                state: row.get(2)?,
                mls_epoch: read_unsigned(row, 3)?,
                membership_epoch: read_unsigned(row, 4)?,
                active_members: read_unsigned(row, 5)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_group_rejoin_hints(database: &Connection) -> Result<Vec<GroupRejoinHint>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT lower(hex(wire_group_id)),local_name,owner_agent_id,last_epoch
             FROM migration_group_hints ORDER BY imported_at_ms,wire_group_id LIMIT 100",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(GroupRejoinHint {
                group_id: row.get(0)?,
                name: row.get(1)?,
                owner_agent_id: row.get(2)?,
                last_epoch: read_unsigned(row, 3)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_transfers(database: &Connection) -> Result<Vec<TransferRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT t.transfer_id,t.content_id,t.state,t.durable_bytes,r.bytes,
                    (SELECT COUNT(*) FROM transfer_sources x
                     WHERE x.transfer_id=t.transfer_id),t.updated_at_ms
             FROM transfers t JOIN reservations r ON r.reservation_id=t.reservation_id
             ORDER BY t.updated_at_ms DESC,t.transfer_id LIMIT 100",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(TransferRow {
                transfer_id: row.get(0)?,
                content_id: row.get(1)?,
                state: row.get(2)?,
                durable_bytes: read_unsigned(row, 3)?,
                file_size: read_unsigned(row, 4)?,
                source_count: read_unsigned(row, 5)?,
                updated_at_ms: row.get(6)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_knowledge(database: &Connection) -> Result<Vec<KnowledgeRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT title,origin,evidence_status,active,updated_at_ms
             FROM resources ORDER BY updated_at_ms DESC,row_id DESC LIMIT 200",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(KnowledgeRow {
                title: row.get(0)?,
                origin: row.get(1)?,
                evidence_status: row.get(2)?,
                active: row.get::<_, i64>(3)? == 1,
                updated_at_ms: row.get(4)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_trust(database: &Connection) -> Result<Vec<TrustRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT a.agent_id,
                    COALESCE(t.ip,0),COALESCE(t.in_,0),COALESCE(t.ap,0),COALESCE(t.an,0),
                    COALESCE(t.ep,0),COALESCE(t.en,0),COALESCE(t.pp,0),COALESCE(t.pn,0),
                    COALESCE(c.total,0),p.agent_id IS NOT NULL
             FROM agents a
             LEFT JOIN (
                 SELECT agent_id,
                    SUM(dimension='integrity' AND outcome='positive') AS ip,
                    SUM(dimension='integrity' AND outcome='negative') AS in_,
                    SUM(dimension='availability' AND outcome='positive') AS ap,
                    SUM(dimension='availability' AND outcome='negative') AS an,
                    SUM(dimension='evidence' AND outcome='positive') AS ep,
                    SUM(dimension='evidence' AND outcome='negative') AS en,
                    SUM(dimension='promise' AND outcome='positive') AS pp,
                    SUM(dimension='promise' AND outcome='negative') AS pn
                 FROM trust_events GROUP BY agent_id
             ) t ON t.agent_id=a.agent_id
             LEFT JOIN (
                 SELECT agent_id,COUNT(*) AS total FROM contribution_events GROUP BY agent_id
             ) c ON c.agent_id=a.agent_id
             LEFT JOIN preferred_peers p ON p.agent_id=a.agent_id
             WHERE t.agent_id IS NOT NULL OR c.agent_id IS NOT NULL OR p.agent_id IS NOT NULL
             ORDER BY a.agent_id LIMIT 200",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            Ok(TrustRow {
                agent_id: row.get(0)?,
                integrity: [read_unsigned(row, 1)?, read_unsigned(row, 2)?],
                availability: [read_unsigned(row, 3)?, read_unsigned(row, 4)?],
                evidence: [read_unsigned(row, 5)?, read_unsigned(row, 6)?],
                promise: [read_unsigned(row, 7)?, read_unsigned(row, 8)?],
                contributions: read_unsigned(row, 9)?,
                preferred: row.get(10)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_access(database: &Connection) -> Result<Vec<AccessRow>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT kind,grant_id,root_path,scope,state,epoch,extensions_json,
                    max_bytes,model_policy,allow_derived_disclosure,indexed_files FROM (
                 SELECT 'share' AS kind,grant_id,root_path,
                        CASE audience
                            WHEN 'group' THEN 'group:' || group_id
                            WHEN 'peers' THEN 'peers:' ||
                                (SELECT COUNT(*) FROM grant_agents a WHERE a.grant_id=g.grant_id) ||
                                '|' || COALESCE((
                                    SELECT group_concat(agent_id, ',') FROM (
                                        SELECT agent_id FROM grant_agents a
                                        WHERE a.grant_id=g.grant_id
                                        ORDER BY agent_id LIMIT 8
                                    )
                                ), '')
                            ELSE audience
                        END AS scope,
                        status AS state,epoch,extensions_json,max_snapshot_bytes AS max_bytes,
                        model_policy,allow_derived_disclosure,
                        (SELECT COUNT(*) FROM resources r WHERE r.grant_id=g.grant_id
                         AND r.active=1 AND r.origin='local') AS indexed_files
                 FROM grants g
                 UNION ALL
                 SELECT kind,write_grant_id,root_path,kind,status,epoch,
                        NULL,max_bytes,NULL,0,0
                 FROM write_grants
             ) ORDER BY kind,grant_id LIMIT 200",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| {
            let path: String = row.get(2)?;
            let directory = Path::new(&path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("directory")
                .to_owned();
            let extensions = row
                .get::<_, Option<String>>(6)?
                .map(|json| {
                    serde_json::from_str::<Vec<String>>(&json)
                        .map(|values| values.join(", "))
                        .map_err(|_| rusqlite::Error::InvalidQuery)
                })
                .transpose()?
                .unwrap_or_default();
            Ok(AccessRow {
                indexed_files: read_unsigned(row, 10)?,
                kind: row.get(0)?,
                id: row.get(1)?,
                directory,
                directory_path: path,
                scope: row.get(3)?,
                state: row.get(4)?,
                epoch: read_unsigned(row, 5)?,
                extensions,
                max_bytes: row
                    .get::<_, Option<i64>>(7)?
                    .map(|value| unsigned(7, value))
                    .transpose()?
                    .unwrap_or_default(),
                model_policy: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                allow_derived_disclosure: row.get::<_, i64>(9)? == 1,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn read_unsigned(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    unsigned(column, row.get(column)?)
}

pub(crate) fn unsigned(column: usize, value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

#[cfg(test)]
mod tests {
    #[test]
    fn projects_migration_group_hints_without_creating_mls_rooms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        let owner = bs58::encode([1; 32]).into_string();
        store
            .connection
            .execute("INSERT INTO agents(agent_id) VALUES (?1)", [&owner])
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO migration_group_hints(
                    wire_group_id,local_name,owner_agent_id,last_epoch,imported_at_ms)
                 VALUES (?1,'Migrated room',?2,9,1)",
                rusqlite::params![[2u8; 32].as_slice(), owner],
            )
            .unwrap();
        let view = super::Dashboard::load(&path).unwrap();
        assert!(view.groups.is_empty());
        assert_eq!(view.group_rejoin_hints.len(), 1);
        assert_eq!(view.group_rejoin_hints[0].group_id, "02".repeat(32));
        assert_eq!(view.group_rejoin_hints[0].name, "Migrated room");
        assert_eq!(view.group_rejoin_hints[0].owner_agent_id, owner);
        assert_eq!(view.group_rejoin_hints[0].last_epoch, 9);
    }

    #[test]
    fn host_inbox_reminder_coalesces_expires_and_grants_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        let now = super::current_time_ms() as u64;
        let id = super::Id128([3; 16]);
        store.request_host_inbox(id, now).unwrap();
        store.request_host_inbox(id, now + 1_000).unwrap();
        let view = super::Dashboard::load(&path).unwrap();
        assert!(
            view.host_inbox_request == Some(id)
                && view.access.is_empty()
                && view.download_approvals.is_empty()
        );
        assert!(
            crate::host_inbox::pending_request(&store.connection, now + 600_000)
                .unwrap()
                .is_none()
        );
        let other = super::Id128([4; 16]);
        assert!(store.decide_host_inbox(other, None, now + 2_000).is_err());
        assert!(
            store
                .decide_host_inbox(id, Some(other), now + 2_000)
                .is_err()
        );
        store.decide_host_inbox(id, None, now + 2_001).unwrap();
        assert!(matches!(
            store.host_inbox_decision(id, now + 2_002),
            Err(asl_types::error::AslError::PolicyDenied)
        ));
        assert!(store.request_host_inbox(other, now + 2_003).is_err());
        store.request_host_inbox(other, now + 600_000).unwrap();
        assert!(store.decide_host_inbox(id, None, now + 600_001).is_err());
    }

    #[test]
    fn activity_includes_local_act_previews_for_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asl.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        let now = super::current_time_ms() as u64;
        for (message, direction, body) in [
            (
                [1; 16],
                crate::act_history::ActDirection::In,
                "incoming act",
            ),
            (
                [2; 16],
                crate::act_history::ActDirection::Out,
                "outgoing act",
            ),
        ] {
            store
                .record_act_history(crate::act_history::ActHistoryRecord {
                    conversation_id: "00112233445566778899aabbccddeeff",
                    message_id: super::Id128(message),
                    mls_epoch: 1,
                    direction,
                    act_kind: 1,
                    reply_to: None,
                    causal_root: super::Id128([3; 16]),
                    body: Some(body),
                    now_ms: now,
                    expires_at_ms: now + 60_000,
                })
                .unwrap();
        }
        let activity = super::Dashboard::load(&path).unwrap().activity;
        assert_eq!(activity.len(), 2);
        assert!(activity.iter().any(|row| {
            row.direction.as_deref() == Some("in") && row.preview.as_deref() == Some("incoming act")
        }));
        assert!(activity.iter().any(|row| {
            row.direction.as_deref() == Some("out")
                && row.preview.as_deref() == Some("outgoing act")
        }));
    }

    #[test]
    fn latest_local_binding_actions_keep_leading_zeroes_and_report_the_core_decision() {
        use crate::contact_bindings::ContactBindingActionKind;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        for code in 0..14 {
            store
                .enqueue_contact_binding_action(
                    ContactBindingActionKind::Lookup,
                    Some(code),
                    None,
                    None,
                    1_000 + code,
                )
                .unwrap();
        }
        let queued = super::Dashboard::load(&path).unwrap().binding_actions;
        assert_eq!(queued.len(), 12);
        assert_eq!(queued[0].code.as_deref(), Some("0000000000000013"));
        assert_eq!(queued[11].requested_at_ms, 1_002);
        assert_eq!(queued[0].state, "queued");
        assert!(queued[0].result.is_none());
        let actions = store.claim_contact_binding_actions().unwrap();
        store
            .finish_contact_binding_action(actions.last().unwrap().id, Err("unavailable"))
            .unwrap();
        let rows = super::Dashboard::load(&path).unwrap().binding_actions;
        assert_eq!(rows[0].state, "failed");
        assert_eq!(rows[0].result.as_deref(), Some("unavailable"));
        assert_eq!(rows[1].state, "working");
    }
    use super::*;

    #[test]
    fn only_reads_an_initialized_database_without_creating_or_migrating() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        assert!(Dashboard::load(&path).is_err());
        assert!(!path.exists());

        drop(crate::open_store(&path).unwrap());
        let result = Dashboard::load(&path).unwrap();
        assert!(result.activity.is_empty());
        assert!(result.direct_observations.is_empty());
        assert!(result.access.is_empty());
        assert_eq!(result.download_mode, "automatic");
        assert_eq!(result.upload_mode, "automatic");
        assert_eq!(result.direct_inbound_mode, "off");
        assert!(result.download_approvals.is_empty());
        assert!(result.upload_approvals.is_empty());
        assert!(result.contact_bindings.is_empty());
        assert!(result.binding_candidates.is_empty());
        assert!(!result.binding_code_public);

        let writer = Connection::open(&path).unwrap();
        writer
            .execute(
                "DELETE FROM schema_migrations WHERE version=?1",
                [SCHEMA_VERSION],
            )
            .unwrap();
        assert!(matches!(
            Dashboard::load(&path),
            Err(AslError::UnsupportedSchemaVersion)
        ));
    }

    #[test]
    fn reads_transfer_modes_without_writing_the_database() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        store
            .set_download_mode(crate::transfers::DownloadMode::Ask)
            .unwrap();
        store
            .set_upload_mode(crate::transfers::UploadMode::Ask)
            .unwrap();
        drop(store);

        let dashboard = Dashboard::load(&path).unwrap();
        assert_eq!(dashboard.download_mode, "ask");
        assert_eq!(dashboard.upload_mode, "ask");
    }

    #[test]
    fn projects_direct_inbound_behavior_from_local_settings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        store
            .set_setting("agent.direct_inbound_mode_v1", "\"browse_only\"", 10)
            .unwrap();
        drop(store);

        let dashboard = Dashboard::load(&path).unwrap();
        assert_eq!(dashboard.direct_inbound_mode, "browse");
    }

    #[test]
    fn projects_unset_inbound_settings_without_saving_the_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        let direct_key = "agent.direct_inbound_mode_v1";
        let group_key = "agent.group_inbound_policy_v1";

        let dashboard = Dashboard::load(&path).unwrap();
        assert_eq!(dashboard.direct_inbound_mode, "off");
        assert!(dashboard.direct_inbound_unset);
        assert!(dashboard.group_inbound_unset);
        assert!(dashboard.group_inbound.browse_enabled);
        assert!(!dashboard.group_inbound.answer_enabled);
        assert_eq!(store.get_setting(direct_key).unwrap(), None);
        assert_eq!(store.get_setting(group_key).unwrap(), None);

        store.set_setting(direct_key, "\"off\"", 1).unwrap();
        GroupInboundPolicy::default().save(&store, 1).unwrap();
        let dashboard = Dashboard::load(&path).unwrap();
        assert_eq!(dashboard.direct_inbound_mode, "off");
        assert!(!dashboard.direct_inbound_unset);
        assert!(!dashboard.group_inbound_unset);
    }

    #[test]
    fn reads_only_the_public_local_identity_projection() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        store
            .set_local_identity_projection(&LocalIdentityProjection {
                agent_id: "agent-public-id".into(),
                peer_id: "device-public-peer".into(),
                network_state: "registry_anchor_missing".into(),
                binding_code: "0000000000000042".into(),
            })
            .unwrap();

        let dashboard = Dashboard::load(&path).unwrap();
        assert_eq!(
            dashboard.identity.agent_id.as_deref(),
            Some("agent-public-id")
        );
        assert_eq!(
            dashboard.identity.peer_id.as_deref(),
            Some("device-public-peer")
        );
        assert_eq!(
            dashboard.identity.identity_state.as_deref(),
            Some("pending_anchor")
        );
        assert_eq!(
            dashboard.identity.network_state.as_deref(),
            Some("registry_anchor_missing")
        );
        assert_eq!(
            dashboard.identity.binding_code.as_deref(),
            Some("0000000000000042")
        );
    }

    #[test]
    fn exposes_only_local_binding_candidates_and_publication_preference() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        let agent = AgentId([31; 32]);
        let peer_key = libp2p_identity::Keypair::ed25519_from_bytes([32; 32]).unwrap();
        let peer =
            asl_types::ids::PeerId::from_bytes(peer_key.public().to_peer_id().to_bytes()).unwrap();
        let code = short_code(agent);
        assert!(
            store
                .record_contact_binding_candidate(agent, &peer, code, 10)
                .unwrap()
        );
        store.set_binding_code_public(true, 11).unwrap();
        drop(store);

        let dashboard = Dashboard::load(&path).unwrap();
        assert!(dashboard.binding_code_public);
        assert_eq!(dashboard.binding_candidates.len(), 1);
        assert_eq!(
            dashboard.binding_candidates[0].agent_id,
            bs58::encode(agent.as_bytes()).into_string()
        );
        assert_eq!(
            dashboard.binding_candidates[0].peer_id,
            bs58::encode(peer.as_bytes()).into_string()
        );
        assert_eq!(dashboard.binding_candidates[0].code, format!("{code:016}"));
        assert!(!dashboard.binding_candidates[0].dismissed);
    }

    #[test]
    fn projects_directory_authorizations_for_local_management() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let store = crate::open_store(&path).unwrap();
        let share_path = temp.path().join("private library");
        let inbox_path = temp.path().join("received files");
        store
            .connection
            .execute(
                "INSERT INTO grants(
                    grant_id,root_path,volume_id,root_file_id,extensions_json,audience,
                    group_id,model_policy,max_snapshot_bytes,epoch,status,created_at_ms,
                    allow_derived_disclosure
                 ) VALUES (?1,?2,'0000000000000001','01010101010101010101010101010101',
                           '[\"md\",\"pdf\"]','public',NULL,'never',2097152,3,'active',10,1)",
                rusqlite::params![
                    "11111111111111111111111111111111",
                    share_path.to_str().unwrap()
                ],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO write_grants(
                    write_grant_id,kind,root_path,max_bytes,epoch,status,root_volume,root_file_id
                 ) VALUES (?1,'inbox',?2,4194304,2,'active',
                           '0000000000000001','02020202020202020202020202020202')",
                rusqlite::params![
                    "22222222222222222222222222222222",
                    inbox_path.to_str().unwrap()
                ],
            )
            .unwrap();
        drop(store);

        let dashboard = Dashboard::load(&path).unwrap();
        let share = dashboard
            .access
            .iter()
            .find(|row| row.kind == "share")
            .unwrap();
        assert_eq!(share.directory, "private library");
        assert_eq!(share.directory_path, share_path.to_str().unwrap());
        assert_eq!(share.scope, "public");
        assert_eq!(share.extensions, "md, pdf");
        assert_eq!(share.max_bytes, 2 * 1024 * 1024);
        assert_eq!(share.model_policy, "never");
        assert!(share.allow_derived_disclosure);

        let inbox = dashboard
            .access
            .iter()
            .find(|row| row.kind == "inbox")
            .unwrap();
        assert_eq!(inbox.directory, "received files");
        assert_eq!(inbox.directory_path, inbox_path.to_str().unwrap());
        assert_eq!(inbox.max_bytes, 4 * 1024 * 1024);
        assert!(inbox.extensions.is_empty());
    }
}
