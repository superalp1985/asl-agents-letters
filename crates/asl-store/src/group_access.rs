//! Owner-authoritative group access policy. These rows are a local
//! projection of owner messages carried inside MLS application plaintext.

use std::collections::BTreeMap;

use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    protocol::{
        GROUP_ALLOW_MEMBER_FILES, GROUP_ALLOW_MEMBER_TEXT, GROUP_ALLOWED_PERMISSION_BITS,
        GroupControl,
    },
    task::GroupId,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, database_error};

pub const DEFAULT_GROUP_PERMISSIONS: u8 = GROUP_ALLOW_MEMBER_TEXT | GROUP_ALLOW_MEMBER_FILES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupAccessKind {
    Text,
    Files,
    Invite,
}

impl GroupAccessKind {
    fn permission_bit(self) -> u8 {
        match self {
            Self::Text => GROUP_ALLOW_MEMBER_TEXT,
            Self::Files => GROUP_ALLOW_MEMBER_FILES,
            Self::Invite => asl_types::protocol::GROUP_ALLOW_MEMBER_INVITE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupMemberRole {
    Owner,
    Admin,
    Member,
}

impl GroupMemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupAccessPolicy {
    pub revision: u64,
    pub permissions: u8,
    pub admins: Vec<PeerId>,
    pub muted: Vec<PeerId>,
}

impl Default for GroupAccessPolicy {
    fn default() -> Self {
        Self {
            revision: 0,
            permissions: DEFAULT_GROUP_PERMISSIONS,
            admins: Vec::new(),
            muted: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMemberAccess {
    pub peer: PeerId,
    pub role: GroupMemberRole,
    pub muted: bool,
    pub can_send_text: bool,
    pub can_send_files: bool,
    pub can_invite: bool,
}

impl Store {
    pub fn group_access_policy(&self, group_id: &GroupId) -> Result<GroupAccessPolicy, AslError> {
        let group = group_text(group_id);
        let policy = self
            .connection
            .query_row(
                "SELECT revision,permissions FROM group_access_policies WHERE group_id=?1",
                [&group],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((revision, permissions)) = policy else {
            return Ok(GroupAccessPolicy::default());
        };
        let mut statement = self
            .connection
            .prepare(
                "SELECT peer_id,role,muted FROM group_access_members
                 WHERE group_id=?1 ORDER BY peer_id LIMIT 513",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([&group], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if rows.len() > 512 {
            return Err(AslError::InvalidDatabase);
        }
        let mut admins = Vec::new();
        let mut muted = Vec::new();
        for (peer, role, muted_value) in rows {
            let peer = parse_peer(&peer)?;
            match role.as_str() {
                "admin" => admins.push(peer.clone()),
                "member" => {}
                _ => return Err(AslError::InvalidDatabase),
            }
            if muted_value == 1 {
                muted.push(peer);
            } else if muted_value != 0 {
                return Err(AslError::InvalidDatabase);
            }
        }
        Ok(GroupAccessPolicy {
            revision: u64::try_from(revision).map_err(|_| AslError::InvalidDatabase)?,
            permissions: u8::try_from(permissions).map_err(|_| AslError::InvalidDatabase)?,
            admins,
            muted,
        })
    }

    /// Apply a complete owner snapshot. Only the MLS room creator may change
    /// the policy, and the revision must move forward.
    pub fn apply_group_control(
        &mut self,
        group_id: &GroupId,
        sender: &PeerId,
        control: &GroupControl,
        now_ms: u64,
    ) -> Result<GroupAccessPolicy, AslError> {
        if control.permissions & !GROUP_ALLOWED_PERMISSION_BITS != 0
            || control.policy_revision == 0
            || control.admins.len() > 512
            || control.muted.len() > 512
        {
            return Err(AslError::InvalidMessage);
        }
        let group = group_text(group_id);
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let creator: String = tx
            .query_row(
                "SELECT creator_peer_id FROM asl_groups WHERE group_id=?1
                 AND state IN ('active','needs_sync')",
                [&group],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if creator != peer_text(sender) {
            return Err(AslError::PolicyDenied);
        }
        let previous: Option<i64> = tx
            .query_row(
                "SELECT revision FROM group_access_policies WHERE group_id=?1",
                [&group],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        if previous.is_some_and(|previous| control.policy_revision <= previous as u64) {
            return Err(AslError::PolicyVersionConflict);
        }
        let active = active_peers(&tx, &group)?;
        let owner = parse_peer(&creator)?;
        if control.admins.iter().chain(&control.muted).any(|peer| {
            !active.iter().any(|candidate| candidate == peer)
                || (peer == &owner && control.muted.contains(peer))
        }) {
            return Err(AslError::PolicyDenied);
        }
        tx.execute(
            "INSERT INTO group_access_policies(group_id,revision,permissions,updated_at_ms)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(group_id) DO UPDATE SET
               revision=excluded.revision,permissions=excluded.permissions,
               updated_at_ms=excluded.updated_at_ms",
            params![
                group,
                i64::try_from(control.policy_revision).map_err(|_| AslError::InvalidMessage)?,
                i64::from(control.permissions),
                now,
            ],
        )
        .map_err(database_error)?;
        tx.execute(
            "DELETE FROM group_access_members WHERE group_id=?1",
            [&group],
        )
        .map_err(database_error)?;
        let mut rows = BTreeMap::new();
        for peer in &control.admins {
            rows.insert(peer.as_bytes().to_vec(), ("admin", false));
        }
        for peer in &control.muted {
            rows.entry(peer.as_bytes().to_vec())
                .and_modify(|entry| entry.1 = true)
                .or_insert(("member", true));
        }
        for (peer, (role, muted)) in rows {
            let peer = PeerId::from_bytes(peer.clone()).map_err(|_| AslError::InvalidMessage)?;
            tx.execute(
                "INSERT INTO group_access_members(group_id,peer_id,role,muted,updated_at_ms)
                 VALUES (?1,?2,?3,?4,?5)",
                params![group, peer_text(&peer), role, i64::from(muted), now],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)?;
        Ok(GroupAccessPolicy {
            revision: control.policy_revision,
            permissions: control.permissions,
            admins: control.admins.clone(),
            muted: control.muted.clone(),
        })
    }

    pub fn group_can_send(
        &self,
        group_id: &GroupId,
        peer: &PeerId,
        kind: GroupAccessKind,
    ) -> Result<bool, AslError> {
        let group = group_text(group_id);
        let creator: String = self
            .connection
            .query_row(
                "SELECT creator_peer_id FROM asl_groups WHERE group_id=?1
                 AND state IN ('active','needs_sync')",
                [&group],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if creator == peer_text(peer) {
            return Ok(true);
        }
        let active: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM group_members
                 WHERE group_id=?1 AND peer_id=?2 AND state='active')",
                params![group, peer_text(peer)],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !active {
            return Ok(false);
        }
        let row = self
            .connection
            .query_row(
                "SELECT p.permissions,r.role,coalesce(r.muted,0)
                 FROM asl_groups g
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 LEFT JOIN group_access_members r ON r.group_id=g.group_id AND r.peer_id=?2
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                params![group, peer_text(peer)],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(database_error)?;
        if row.2 != 0 {
            return Ok(false);
        }
        if row.1.as_deref() == Some("admin") {
            return Ok(true);
        }
        let permissions = row
            .0
            .map(u8::try_from)
            .transpose()
            .map_err(|_| AslError::InvalidDatabase)?
            .unwrap_or(DEFAULT_GROUP_PERMISSIONS);
        Ok(permissions & kind.permission_bit() != 0)
    }

    pub fn group_members(&self, group_id: &GroupId) -> Result<Vec<GroupMemberAccess>, AslError> {
        let group = group_text(group_id);
        let creator: String = self
            .connection
            .query_row(
                "SELECT creator_peer_id FROM asl_groups WHERE group_id=?1
                 AND state IN ('active','needs_sync')",
                [&group],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let policy = self.group_access_policy(group_id)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT m.peer_id,coalesce(r.role,'member'),coalesce(r.muted,0)
                 FROM group_members m
                 LEFT JOIN group_access_members r
                   ON r.group_id=m.group_id AND r.peer_id=m.peer_id
                 WHERE m.group_id=?1 AND m.state='active'
                 ORDER BY m.peer_id LIMIT 513",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([&group], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if rows.len() > 512 {
            return Err(AslError::InvalidDatabase);
        }
        rows.into_iter()
            .map(|(peer, role, muted)| {
                let peer = parse_peer(&peer)?;
                let role = if peer_text(&peer) == creator {
                    GroupMemberRole::Owner
                } else if role == "admin" {
                    GroupMemberRole::Admin
                } else if role == "member" {
                    GroupMemberRole::Member
                } else {
                    return Err(AslError::InvalidDatabase);
                };
                let muted = muted == 1;
                let can_send_text = if role == GroupMemberRole::Owner {
                    true
                } else if muted {
                    false
                } else if role == GroupMemberRole::Admin {
                    true
                } else {
                    policy.permissions & GROUP_ALLOW_MEMBER_TEXT != 0
                };
                let can_send_files = if role == GroupMemberRole::Owner {
                    true
                } else if muted {
                    false
                } else if role == GroupMemberRole::Admin {
                    true
                } else {
                    policy.permissions & GROUP_ALLOW_MEMBER_FILES != 0
                };
                let can_invite = if role == GroupMemberRole::Owner {
                    true
                } else if muted {
                    false
                } else if role == GroupMemberRole::Admin {
                    true
                } else {
                    policy.permissions & asl_types::protocol::GROUP_ALLOW_MEMBER_INVITE != 0
                };
                Ok(GroupMemberAccess {
                    peer,
                    role,
                    muted,
                    can_send_text,
                    can_send_files,
                    can_invite,
                })
            })
            .collect()
    }

    pub fn group_access_owner(&self, wire_id: Hash32) -> Result<Option<PeerId>, AslError> {
        let creator: Option<String> = self
            .connection
            .query_row(
                "SELECT g.creator_peer_id FROM asl_groups g
                 JOIN mls_room_states s ON s.local_group_id=g.group_id
                 WHERE s.wire_group_id=?1 AND g.state IN ('active','needs_sync')",
                [wire_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        creator.map(|text| parse_peer(&text)).transpose()
    }
}

fn group_text(group_id: &GroupId) -> String {
    hex::encode(group_id.0.as_bytes())
}

fn peer_text(peer: &PeerId) -> String {
    bs58::encode(peer.as_bytes()).into_string()
}

fn parse_peer(text: &str) -> Result<PeerId, AslError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
}

fn active_peers(tx: &rusqlite::Transaction<'_>, group_id: &str) -> Result<Vec<PeerId>, AslError> {
    let mut statement = tx
        .prepare("SELECT peer_id FROM group_members WHERE group_id=?1 AND state='active' ORDER BY peer_id LIMIT 513")
        .map_err(database_error)?;
    let rows = statement
        .query_map([group_id], |row| row.get::<_, String>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    if rows.len() > 512 {
        return Err(AslError::InvalidDatabase);
    }
    rows.into_iter().map(|text| parse_peer(&text)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::ids::{AgentId, Id128};
    use rusqlite::params;

    fn peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32])
            .unwrap()
            .public()
            .to_peer_id();
        PeerId::from_bytes(key.to_bytes()).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, Store, GroupId, PeerId, PeerId, PeerId) {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::open_store(&directory.path().join("store.sqlite3")).unwrap();
        let owner = peer(1);
        let admin = peer(2);
        let member = peer(3);
        let group = GroupId(Id128([4; 16]));
        let agent = AgentId([5; 32]);
        store
            .connection
            .execute(
                "INSERT INTO agents(agent_id) VALUES (?1)",
                [bs58::encode(agent.0).into_string()],
            )
            .unwrap();
        for (serial, peer) in [&owner, &admin, &member].into_iter().enumerate() {
            let agent_text = bs58::encode(agent.0).into_string();
            store
                .connection
                .execute(
                    "INSERT INTO device_identities(
                        peer_id,agent_id,public_key_hex,certificate_cbor,
                        certificate_serial,certificate_expires_ms,created_at_ms)
                     VALUES (?1,?2,?3,X'',?4,100,1)",
                    params![
                        peer_text(peer),
                        agent_text.clone(),
                        "00".repeat(32),
                        i64::try_from(serial + 1).unwrap(),
                    ],
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
                    params![peer_text(peer), agent_text],
                )
                .unwrap();
        }
        let group_text = hex::encode(group.0.as_bytes());
        store
            .connection
            .execute(
                "INSERT INTO asl_groups(
                    group_id,creator_peer_id,local_name,mls_epoch,membership_epoch,state,
                    created_at_ms,updated_at_ms)
                 VALUES (?1,?2,'test',0,1,'active',1,1)",
                params![group_text, peer_text(&owner)],
            )
            .unwrap();
        for (peer, role) in [(&owner, "creator"), (&admin, "member"), (&member, "member")] {
            store
                .connection
                .execute(
                    "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
                     VALUES (?1,?2,?3,'active',1)",
                    params![hex::encode(group.0.as_bytes()), peer_text(peer), role],
                )
                .unwrap();
        }
        (directory, store, group, owner, admin, member)
    }

    #[test]
    fn owner_policy_enforces_roles_mute_and_revision() {
        let (_directory, mut store, group, owner, admin, member) = fixture();
        let control = GroupControl {
            message_id: Id128([7; 16]),
            policy_revision: 1,
            permissions: GROUP_ALLOW_MEMBER_TEXT,
            admins: vec![admin.clone()],
            muted: vec![member.clone()],
        };
        let policy = store
            .apply_group_control(&group, &owner, &control, 10)
            .unwrap();
        assert_eq!(policy.revision, 1);
        assert!(
            store
                .group_can_send(&group, &owner, GroupAccessKind::Files)
                .unwrap()
        );
        assert!(
            store
                .group_can_send(&group, &admin, GroupAccessKind::Text)
                .unwrap()
        );
        assert!(
            !store
                .group_can_send(&group, &member, GroupAccessKind::Text)
                .unwrap()
        );
        let members = store.group_members(&group).unwrap();
        assert_eq!(members.len(), 3);
        assert!(
            members
                .iter()
                .any(|m| m.role == GroupMemberRole::Owner && m.peer == owner)
        );
        assert!(
            members
                .iter()
                .any(|m| m.role == GroupMemberRole::Admin && m.peer == admin)
        );
        assert!(matches!(
            store.apply_group_control(&group, &owner, &control, 11),
            Err(AslError::PolicyVersionConflict)
        ));
    }

    #[test]
    fn non_owner_cannot_replace_policy() {
        let (_directory, mut store, group, _owner, _admin, member) = fixture();
        let control = GroupControl {
            message_id: Id128([8; 16]),
            policy_revision: 1,
            permissions: GROUP_ALLOW_MEMBER_TEXT,
            admins: Vec::new(),
            muted: Vec::new(),
        };
        assert!(matches!(
            store.apply_group_control(&group, &member, &control, 10),
            Err(AslError::PolicyDenied)
        ));
        assert_eq!(
            store.group_access_policy(&group).unwrap(),
            GroupAccessPolicy::default()
        );
    }
}
