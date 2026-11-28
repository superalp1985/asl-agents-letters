//! Owner-authoritative group access policy. These rows are a local
//! projection of owner messages carried inside MLS application plaintext.

use std::collections::BTreeMap;

use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    protocol::{
        GROUP_ADMIN_MANAGE_FILES, GROUP_ADMIN_MANAGE_INVITES, GROUP_ADMIN_MANAGE_MEMBERS,
        GROUP_ALLOW_MEMBER_FILES, GROUP_ALLOW_MEMBER_TEXT, GROUP_ALLOWED_ADMIN_CAPABILITY_BITS,
        GROUP_ALLOWED_FILE_PERMISSION_BITS, GROUP_ALLOWED_PERMISSION_BITS, GROUP_FILE_FETCH,
        GROUP_FILE_READ, GROUP_FILE_SEND, GroupAdminCapability, GroupControl, GroupFilePolicy,
        MAX_GROUP_CONTROL_FILE_POLICIES, MAX_GROUP_CONTROL_PEERS,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupFileAccessKind {
    Read,
    Send,
    Fetch,
}

impl GroupFileAccessKind {
    fn permission_bit(self) -> u8 {
        match self {
            Self::Read => GROUP_FILE_READ,
            Self::Send => GROUP_FILE_SEND,
            Self::Fetch => GROUP_FILE_FETCH,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupAdminCapabilityKind {
    ManageMembers,
    ManageFiles,
    ManageInvites,
}

impl GroupAdminCapabilityKind {
    fn permission_bit(self) -> u8 {
        match self {
            Self::ManageMembers => GROUP_ADMIN_MANAGE_MEMBERS,
            Self::ManageFiles => GROUP_ADMIN_MANAGE_FILES,
            Self::ManageInvites => GROUP_ADMIN_MANAGE_INVITES,
        }
    }
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
    pub owner: Option<PeerId>,
    pub file_policies: Vec<GroupFilePolicy>,
    pub admin_capabilities: Vec<GroupAdminCapability>,
}

impl Default for GroupAccessPolicy {
    fn default() -> Self {
        Self {
            revision: 0,
            permissions: DEFAULT_GROUP_PERMISSIONS,
            admins: Vec::new(),
            muted: Vec::new(),
            owner: None,
            file_policies: Vec::new(),
            admin_capabilities: Vec::new(),
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
                "SELECT p.revision,p.permissions,coalesce(p.owner_peer_id,g.creator_peer_id)
                 FROM asl_groups g
                 JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                [&group],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((revision, permissions, owner)) = policy else {
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
        if rows.len() > MAX_GROUP_CONTROL_PEERS {
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
        let file_policies = self.group_file_policies(group_id)?;
        let admin_capabilities = self.group_admin_capabilities(group_id)?;
        Ok(GroupAccessPolicy {
            revision: u64::try_from(revision).map_err(|_| AslError::InvalidDatabase)?,
            permissions: u8::try_from(permissions).map_err(|_| AslError::InvalidDatabase)?,
            admins,
            muted,
            owner: Some(parse_peer(&owner)?),
            file_policies,
            admin_capabilities,
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
            || control.admins.len() > MAX_GROUP_CONTROL_PEERS
            || control.muted.len() > MAX_GROUP_CONTROL_PEERS
            || control.file_policies.len() > MAX_GROUP_CONTROL_FILE_POLICIES
            || control.admin_capabilities.len() > MAX_GROUP_CONTROL_PEERS
            || !unique_peers(&control.admins)
            || !unique_peers(&control.muted)
            || !unique_file_policies(&control.file_policies)
            || !unique_admin_capabilities(&control.admin_capabilities)
            || control
                .file_policies
                .iter()
                .any(|policy| policy.permissions & !GROUP_ALLOWED_FILE_PERMISSION_BITS != 0)
            || control.admin_capabilities.iter().any(|capability| {
                capability.capabilities & !GROUP_ALLOWED_ADMIN_CAPABILITY_BITS != 0
                    || !control.admins.contains(&capability.peer)
            })
        {
            return Err(AslError::InvalidMessage);
        }
        let mut admins = control.admins.clone();
        admins.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut muted = control.muted.clone();
        muted.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut file_policies = control.file_policies.clone();
        file_policies
            .sort_by(|left, right| left.content_id.as_bytes().cmp(right.content_id.as_bytes()));
        let mut admin_capabilities = control.admin_capabilities.clone();
        admin_capabilities.sort_by(|left, right| left.peer.as_bytes().cmp(right.peer.as_bytes()));
        let group = group_text(group_id);
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let (creator, prior_owner): (String, Option<String>) = tx
            .query_row(
                "SELECT g.creator_peer_id,p.owner_peer_id
                 FROM asl_groups g
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                [&group],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(database_error)?;
        let current_owner = prior_owner.as_deref().unwrap_or(&creator);
        if current_owner != peer_text(sender) {
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
        let owner_text = control
            .owner
            .as_ref()
            .map(peer_text)
            .unwrap_or_else(|| current_owner.to_owned());
        let owner = parse_peer(&owner_text)?;
        if !active.iter().any(|candidate| candidate == &owner) {
            return Err(AslError::PolicyDenied);
        }
        if control.admins.iter().chain(&control.muted).any(|peer| {
            !active.iter().any(|candidate| candidate == peer)
                || (peer == &owner && control.muted.contains(peer))
        }) {
            return Err(AslError::PolicyDenied);
        }
        tx.execute(
            "INSERT INTO group_access_policies(group_id,revision,permissions,owner_peer_id,updated_at_ms)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(group_id) DO UPDATE SET
               revision=excluded.revision,permissions=excluded.permissions,
               owner_peer_id=excluded.owner_peer_id,
               updated_at_ms=excluded.updated_at_ms",
            params![
                group,
                i64::try_from(control.policy_revision).map_err(|_| AslError::InvalidMessage)?,
                i64::from(control.permissions),
                owner_text,
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
        tx.execute(
            "DELETE FROM group_file_policies WHERE group_id=?1",
            [&group],
        )
        .map_err(database_error)?;
        for policy in &file_policies {
            tx.execute(
                "INSERT INTO group_file_policies(
                    group_id,content_id,permissions,updated_at_ms)
                 VALUES (?1,?2,?3,?4)",
                params![
                    group,
                    policy.content_id.as_bytes().as_slice(),
                    i64::from(policy.permissions),
                    now,
                ],
            )
            .map_err(database_error)?;
        }
        tx.execute(
            "DELETE FROM group_admin_capabilities WHERE group_id=?1",
            [&group],
        )
        .map_err(database_error)?;
        for capability in &admin_capabilities {
            tx.execute(
                "INSERT INTO group_admin_capabilities(
                    group_id,peer_id,capabilities,updated_at_ms)
                 VALUES (?1,?2,?3,?4)",
                params![
                    group,
                    peer_text(&capability.peer),
                    i64::from(capability.capabilities),
                    now,
                ],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)?;
        Ok(GroupAccessPolicy {
            revision: control.policy_revision,
            permissions: control.permissions,
            admins,
            muted,
            owner: Some(owner),
            file_policies,
            admin_capabilities,
        })
    }

    pub fn group_can_send(
        &self,
        group_id: &GroupId,
        peer: &PeerId,
        kind: GroupAccessKind,
    ) -> Result<bool, AslError> {
        let group = group_text(group_id);
        let owner: String = self
            .connection
            .query_row(
                "SELECT coalesce(p.owner_peer_id,g.creator_peer_id)
                 FROM asl_groups g
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                [&group],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if owner == peer_text(peer) {
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

    /// Applies capability-scoped administrator slices without changing the
    /// owner policy revision or any owner-only field.
    pub fn apply_group_moderation(
        &mut self,
        group_id: &GroupId,
        sender: &PeerId,
        control: &GroupControl,
        now_ms: u64,
    ) -> Result<GroupAccessPolicy, AslError> {
        control.encode()?;
        let current = self.group_access_policy(group_id)?;
        let owner = current.owner.clone().ok_or(AslError::InvalidDatabase)?;
        if sender == &owner
            || control.policy_revision != current.revision
            || control.permissions != current.permissions
            || control.admins != current.admins
            || control.owner.as_ref() != Some(&owner)
            || control.admin_capabilities != current.admin_capabilities
            || control.muted.len() > MAX_GROUP_CONTROL_PEERS
        {
            return Err(AslError::PolicyDenied);
        }
        let members_changed = control.muted != current.muted;
        let files_changed = control.file_policies != current.file_policies;
        if (members_changed
            && !self.group_admin_has_capability(
                group_id,
                sender,
                GroupAdminCapabilityKind::ManageMembers,
            )?)
            || (files_changed
                && !self.group_admin_has_capability(
                    group_id,
                    sender,
                    GroupAdminCapabilityKind::ManageFiles,
                )?)
        {
            return Err(AslError::PolicyDenied);
        }
        let active = self.group_topology_members(group_id)?;
        if control
            .muted
            .iter()
            .any(|peer| peer == &owner || !active.contains(peer))
        {
            return Err(AslError::PolicyDenied);
        }
        let group = group_text(group_id);
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if members_changed {
            tx.execute(
                "UPDATE group_access_members SET muted=0,updated_at_ms=?2 WHERE group_id=?1",
                params![group, now],
            )
            .map_err(database_error)?;
            for peer in &control.muted {
                tx.execute(
                    "INSERT INTO group_access_members(group_id,peer_id,role,muted,updated_at_ms)
                     VALUES (?1,?2,'member',1,?3)
                     ON CONFLICT(group_id,peer_id) DO UPDATE SET
                       muted=1,updated_at_ms=excluded.updated_at_ms",
                    params![group, peer_text(peer), now],
                )
                .map_err(database_error)?;
            }
        }
        if files_changed {
            tx.execute(
                "DELETE FROM group_file_policies WHERE group_id=?1",
                [&group],
            )
            .map_err(database_error)?;
            for policy in &control.file_policies {
                tx.execute(
                    "INSERT INTO group_file_policies(
                        group_id,content_id,permissions,updated_at_ms)
                     VALUES (?1,?2,?3,?4)",
                    params![
                        group,
                        policy.content_id.as_bytes().as_slice(),
                        i64::from(policy.permissions),
                        now,
                    ],
                )
                .map_err(database_error)?;
            }
        }
        tx.commit().map_err(database_error)?;
        Ok(GroupAccessPolicy {
            muted: control.muted.clone(),
            file_policies: control.file_policies.clone(),
            ..current
        })
    }

    pub fn group_can_access_file(
        &self,
        group_id: &GroupId,
        peer: &PeerId,
        content_id: &Hash32,
        kind: GroupFileAccessKind,
    ) -> Result<bool, AslError> {
        let group = group_text(group_id);
        let owner: String = self
            .connection
            .query_row(
                "SELECT coalesce(p.owner_peer_id,g.creator_peer_id)
                 FROM asl_groups g
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                [&group],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if owner == peer_text(peer) {
            return Ok(true);
        }
        let row = self
            .connection
            .query_row(
                "SELECT p.permissions,r.role,coalesce(r.muted,0),f.permissions
                 FROM asl_groups g
                 JOIN group_members m
                   ON m.group_id=g.group_id AND m.peer_id=?2 AND m.state='active'
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 LEFT JOIN group_access_members r
                   ON r.group_id=g.group_id AND r.peer_id=?2
                 LEFT JOIN group_file_policies f
                   ON f.group_id=g.group_id AND f.content_id=?3
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                params![group, peer_text(peer), content_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((permissions, role, muted, file_permissions)) = row else {
            return Ok(false);
        };
        if muted != 0 {
            return Ok(false);
        }
        if let Some(file_permissions) = file_permissions {
            let file_permissions =
                u8::try_from(file_permissions).map_err(|_| AslError::InvalidDatabase)?;
            return Ok(file_permissions & kind.permission_bit() != 0);
        }
        if role.as_deref() == Some("admin") {
            return Ok(true);
        }
        let permissions = permissions
            .map(u8::try_from)
            .transpose()
            .map_err(|_| AslError::InvalidDatabase)?
            .unwrap_or(DEFAULT_GROUP_PERMISSIONS);
        Ok(permissions & GROUP_ALLOW_MEMBER_FILES != 0)
    }

    /// Missing key-8 entries intentionally retain the old v1 admin behavior:
    /// active, unmuted admins have all delegated capabilities.
    pub fn group_admin_has_capability(
        &self,
        group_id: &GroupId,
        peer: &PeerId,
        capability: GroupAdminCapabilityKind,
    ) -> Result<bool, AslError> {
        let group = group_text(group_id);
        let owner: String = self
            .connection
            .query_row(
                "SELECT coalesce(p.owner_peer_id,g.creator_peer_id)
                 FROM asl_groups g
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                [&group],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if owner == peer_text(peer) {
            return Ok(true);
        }
        let row = self
            .connection
            .query_row(
                "SELECT r.role,coalesce(r.muted,0),c.capabilities
                 FROM asl_groups g
                 JOIN group_members m
                   ON m.group_id=g.group_id AND m.peer_id=?2 AND m.state='active'
                 LEFT JOIN group_access_members r
                   ON r.group_id=g.group_id AND r.peer_id=?2
                 LEFT JOIN group_admin_capabilities c
                   ON c.group_id=g.group_id AND c.peer_id=?2
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
                params![group, peer_text(peer)],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((role, muted, capabilities)) = row else {
            return Ok(false);
        };
        if role.as_deref() != Some("admin") || muted != 0 {
            return Ok(false);
        }
        let Some(capabilities) = capabilities else {
            return Ok(true);
        };
        let capabilities = u8::try_from(capabilities).map_err(|_| AslError::InvalidDatabase)?;
        Ok(capabilities & capability.permission_bit() != 0)
    }

    pub fn group_members(&self, group_id: &GroupId) -> Result<Vec<GroupMemberAccess>, AslError> {
        let group = group_text(group_id);
        let owner: String = self
            .connection
            .query_row(
                "SELECT coalesce(p.owner_peer_id,g.creator_peer_id)
                 FROM asl_groups g
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE g.group_id=?1 AND g.state IN ('active','needs_sync')",
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
        if rows.len() > MAX_GROUP_CONTROL_PEERS {
            return Err(AslError::InvalidDatabase);
        }
        rows.into_iter()
            .map(|(peer, role, muted)| {
                let peer = parse_peer(&peer)?;
                let role = if peer_text(&peer) == owner {
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

    pub fn group_file_policies(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<GroupFilePolicy>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT content_id,permissions FROM group_file_policies
                 WHERE group_id=?1 ORDER BY content_id LIMIT 513",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([group_text(group_id)], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if rows.len() > MAX_GROUP_CONTROL_FILE_POLICIES {
            return Err(AslError::InvalidDatabase);
        }
        rows.into_iter()
            .map(|(content_id, permissions)| {
                Ok(GroupFilePolicy {
                    content_id: Hash32(
                        content_id
                            .try_into()
                            .map_err(|_| AslError::InvalidDatabase)?,
                    ),
                    permissions: u8::try_from(permissions)
                        .map_err(|_| AslError::InvalidDatabase)?,
                })
            })
            .collect()
    }

    pub fn group_admin_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<GroupAdminCapability>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT c.peer_id,c.capabilities
                 FROM group_admin_capabilities c
                 JOIN group_members m
                   ON m.group_id=c.group_id AND m.peer_id=c.peer_id AND m.state='active'
                 JOIN group_access_members r
                   ON r.group_id=c.group_id AND r.peer_id=c.peer_id AND r.role='admin'
                 WHERE c.group_id=?1 ORDER BY c.peer_id LIMIT 513",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([group_text(group_id)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if rows.len() > MAX_GROUP_CONTROL_PEERS {
            return Err(AslError::InvalidDatabase);
        }
        rows.into_iter()
            .map(|(peer, capabilities)| {
                Ok(GroupAdminCapability {
                    peer: parse_peer(&peer)?,
                    capabilities: u8::try_from(capabilities)
                        .map_err(|_| AslError::InvalidDatabase)?,
                })
            })
            .collect()
    }

    pub fn group_access_owner(&self, wire_id: Hash32) -> Result<Option<PeerId>, AslError> {
        let owner: Option<String> = self
            .connection
            .query_row(
                "SELECT coalesce(p.owner_peer_id,g.creator_peer_id) FROM asl_groups g
                 JOIN mls_room_states s ON s.local_group_id=g.group_id
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 WHERE s.wire_group_id=?1 AND g.state IN ('active','needs_sync')",
                [wire_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        owner.map(|text| parse_peer(&text)).transpose()
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

fn unique_peers(peers: &[PeerId]) -> bool {
    peers
        .iter()
        .enumerate()
        .all(|(index, peer)| !peers[..index].contains(peer))
}

fn unique_file_policies(policies: &[GroupFilePolicy]) -> bool {
    policies.iter().enumerate().all(|(index, policy)| {
        !policies[..index]
            .iter()
            .any(|candidate| candidate.content_id == policy.content_id)
    })
}

fn unique_admin_capabilities(capabilities: &[GroupAdminCapability]) -> bool {
    capabilities.iter().enumerate().all(|(index, capability)| {
        !capabilities[..index]
            .iter()
            .any(|candidate| candidate.peer == capability.peer)
    })
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
    if rows.len() > MAX_GROUP_CONTROL_PEERS {
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
            owner: None,
            file_policies: Vec::new(),
            admin_capabilities: Vec::new(),
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
            owner: None,
            file_policies: Vec::new(),
            admin_capabilities: Vec::new(),
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

    #[test]
    fn file_policies_and_delegated_admin_capabilities_are_enforced() {
        let (_directory, mut store, group, owner, admin, member) = fixture();
        let admin_file = Hash32([0x21; 32]);
        let member_file = Hash32([0x22; 32]);
        let missing_file = Hash32([0x23; 32]);
        let control = GroupControl {
            message_id: Id128([9; 16]),
            policy_revision: 1,
            permissions: GROUP_ALLOW_MEMBER_TEXT,
            admins: vec![admin.clone()],
            muted: Vec::new(),
            owner: None,
            file_policies: vec![
                GroupFilePolicy {
                    content_id: admin_file,
                    permissions: GROUP_FILE_READ,
                },
                GroupFilePolicy {
                    content_id: member_file,
                    permissions: GROUP_FILE_FETCH | GROUP_FILE_READ,
                },
            ],
            admin_capabilities: vec![GroupAdminCapability {
                peer: admin.clone(),
                capabilities: GROUP_ADMIN_MANAGE_FILES | GROUP_ADMIN_MANAGE_INVITES,
            }],
        };

        store
            .apply_group_control(&group, &owner, &control, 20)
            .unwrap();

        assert!(
            store
                .group_can_access_file(&group, &owner, &missing_file, GroupFileAccessKind::Send)
                .unwrap()
        );
        assert!(
            store
                .group_can_access_file(&group, &admin, &admin_file, GroupFileAccessKind::Read)
                .unwrap()
        );
        assert!(
            !store
                .group_can_access_file(&group, &admin, &admin_file, GroupFileAccessKind::Send)
                .unwrap()
        );
        assert!(
            store
                .group_can_access_file(&group, &member, &member_file, GroupFileAccessKind::Fetch)
                .unwrap()
        );
        assert!(
            !store
                .group_can_access_file(&group, &member, &missing_file, GroupFileAccessKind::Read)
                .unwrap()
        );
        assert!(
            store
                .group_admin_has_capability(&group, &admin, GroupAdminCapabilityKind::ManageFiles)
                .unwrap()
        );
        assert!(
            !store
                .group_admin_has_capability(&group, &admin, GroupAdminCapabilityKind::ManageMembers)
                .unwrap()
        );
        assert!(
            store
                .group_admin_has_capability(&group, &owner, GroupAdminCapabilityKind::ManageMembers)
                .unwrap()
        );

        let policy = store.group_access_policy(&group).unwrap();
        assert_eq!(policy.file_policies, control.file_policies);
        assert_eq!(policy.admin_capabilities, control.admin_capabilities);
    }

    #[test]
    fn v42_adds_only_the_file_and_admin_capability_projections() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite3");
        let store = crate::open_store(&path).unwrap();
        drop(store);

        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE group_admin_capabilities;
                 DROP TABLE group_file_policies;
                 DROP TABLE mls_shard_forward_receipts;
                 DROP TABLE mls_shard_bindings;
                 DROP TABLE mls_room_shards;
                 DROP TABLE group_removal_requests;
                 DROP TABLE conversation_act_semantic_index;
                 DELETE FROM schema_migrations WHERE version>=42;",
            )
            .unwrap();
        drop(connection);

        let store = crate::open_store(&path).unwrap();
        assert_eq!(store.schema_version(), crate::SCHEMA_VERSION as u32);
        for table in ["group_file_policies", "group_admin_capabilities"] {
            let exists: bool = store
                .connection
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1
                     )",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing table {table}");
        }
    }

    #[test]
    fn delegated_admin_can_only_apply_the_muted_field_of_current_policy() {
        let (_directory, mut store, group, owner, admin, member) = fixture();
        let base = GroupControl {
            message_id: Id128([9; 16]),
            policy_revision: 1,
            permissions: GROUP_ALLOW_MEMBER_TEXT,
            admins: vec![admin.clone()],
            muted: Vec::new(),
            owner: None,
            file_policies: Vec::new(),
            admin_capabilities: vec![GroupAdminCapability {
                peer: admin.clone(),
                capabilities: asl_types::protocol::GROUP_ADMIN_MANAGE_MEMBERS,
            }],
        };
        store
            .apply_group_control(&group, &owner, &base, 10)
            .unwrap();
        let moderation = GroupControl {
            message_id: Id128([10; 16]),
            muted: vec![member.clone()],
            owner: Some(owner.clone()),
            ..base
        };
        let policy = store
            .apply_group_moderation(&group, &admin, &moderation, 11)
            .unwrap();
        assert_eq!(policy.muted, vec![member.clone()]);
        assert!(
            !store
                .group_can_send(&group, &member, GroupAccessKind::Text)
                .unwrap()
        );

        let forged = GroupControl {
            message_id: Id128([11; 16]),
            permissions: 0,
            ..moderation
        };
        assert!(matches!(
            store.apply_group_moderation(&group, &admin, &forged, 12),
            Err(AslError::PolicyDenied)
        ));
    }
}
