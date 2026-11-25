//! Single-use local group administration. Only Core issues a selectable view.
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128, PeerId},
};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::sql_number;
use crate::{Store, database_error, read_setting, write_setting};

const KEY: &str = "mls.local_operator.v1";
const VIEW_KEY: &str = "mls.local_operator_view.v1";
const REQUEST_WINDOW_MS: u64 = 30_000;
pub const SNAPSHOT_WINDOW_MS: u64 = 120_000;
pub const VIEW_LIMIT: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminRequest {
    Refresh,
    Create {
        tag: String,
    },
    Invite {
        tag: String,
        room: String,
        connection: String,
    },
    Remove {
        tag: String,
        room: String,
        device: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminOutcome {
    Queued,
    Applying,
    Ready,
    Created,
    InviteQueued,
    MemberRemoved,
    Failed,
    Unconfirmed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminRoom {
    pub room: String,
    pub name: String,
    pub epoch: u64,
    pub membership_epoch: u64,
    pub members: Vec<AdminMember>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminMember {
    pub agent: String,
    pub device: String,
    pub creator: bool,
    pub role: String,
    pub muted: bool,
    pub can_send_text: bool,
    pub can_send_files: bool,
    pub can_invite: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminPeer {
    pub agent: String,
    pub device: String,
    pub connection: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminSnapshot {
    pub tag: String,
    pub rooms: Vec<AdminRoom>,
    pub peers: Vec<AdminPeer>,
    pub expires_ms: u64,
}

impl AdminSnapshot {
    pub fn permits_selection(&self, request: &AdminRequest, now: u64) -> bool {
        self.expires_ms > now
            && match request {
                AdminRequest::Refresh => false,
                AdminRequest::Create { tag } => tag == &self.tag,
                AdminRequest::Invite {
                    tag,
                    room,
                    connection,
                } => {
                    tag == &self.tag
                        && self
                            .rooms
                            .iter()
                            .find(|r| &r.room == room)
                            .is_some_and(|r| {
                                self.peers.iter().any(|p| {
                                    &p.connection == connection
                                        && !r.members.iter().any(|m| m.device == p.device)
                                })
                            })
                }
                AdminRequest::Remove { tag, room, device } => {
                    tag == &self.tag
                        && self
                            .rooms
                            .iter()
                            .find(|r| &r.room == room)
                            .is_some_and(|r| {
                                r.members.iter().any(|m| !m.creator && &m.device == device)
                            })
                }
            }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AdminTicket {
    id: Id128,
    agent: AgentId,
    device: String,
    pub request: AdminRequest,
    outcome: AdminOutcome,
    expires_ms: u64,
}

impl AdminTicket {
    fn active(&self) -> bool {
        matches!(self.outcome, AdminOutcome::Queued | AdminOutcome::Applying)
    }

    fn owned_by(&self, agent: AgentId, device: &PeerId) -> bool {
        self.agent == agent && self.device == bs58::encode(device.as_bytes()).into_string()
    }
}

fn read(db: &Connection, now: u64) -> Result<Option<AdminTicket>, AslError> {
    let Some(raw) = read_setting(db, KEY)? else {
        return Ok(None);
    };
    let mut t: AdminTicket = serde_json::from_str(&raw).map_err(|_| AslError::InvalidDatabase)?;
    if t.active() && t.expires_ms <= now {
        t.outcome = AdminOutcome::Unconfirmed;
    }
    Ok(Some(t))
}

fn save(db: &Connection, t: &AdminTicket, now: u64) -> Result<(), AslError> {
    write_setting(
        db,
        KEY,
        &serde_json::to_string(t).map_err(|_| AslError::InvalidDatabase)?,
        sql_number(now)?,
    )
}

fn current_view(db: &Connection, now: u64) -> Result<Option<AdminSnapshot>, AslError> {
    let Some(raw) = read_setting(db, VIEW_KEY)? else {
        return Ok(None);
    };
    let view: AdminSnapshot = serde_json::from_str(&raw).map_err(|_| AslError::InvalidDatabase)?;
    Ok((view.expires_ms > now).then_some(view))
}

pub(crate) fn projection(
    db: &Connection,
    local: Option<(AgentId, &PeerId)>,
    now: u64,
) -> Result<(Option<AdminSnapshot>, Option<AdminOutcome>), AslError> {
    let Some(t) = read(db, now)?.filter(|t| local.is_some_and(|(a, p)| t.owned_by(a, p))) else {
        return Ok((None, None));
    };
    let view = if t.outcome == AdminOutcome::Ready {
        current_view(db, now)?
    } else {
        None
    };
    Ok((view, Some(t.outcome)))
}

impl Store {
    pub fn local_group_admin_snapshot(
        &self,
        agent: AgentId,
        device: &PeerId,
        now: u64,
    ) -> Result<Option<AdminSnapshot>, AslError> {
        Ok(projection(&self.connection, Some((agent, device)), now)?.0)
    }

    pub fn local_group_admin_status(&self, now: u64) -> Result<Option<AdminOutcome>, AslError> {
        Ok(read(&self.connection, now)?.map(|t| t.outcome))
    }

    pub fn managed_mls_rooms(&self, device: &PeerId) -> Result<Vec<AdminRoom>, AslError> {
        let mut statement = self.connection.prepare(
            "WITH owned AS (
               SELECT g.group_id,g.local_name,g.mls_epoch,g.membership_epoch,g.created_at_ms,s.wire_group_id
               FROM asl_groups g JOIN mls_room_states s ON s.local_group_id=g.group_id
               WHERE g.creator_peer_id=?1 AND g.state='active'
               ORDER BY g.created_at_ms DESC,g.group_id LIMIT ?2
             )
             SELECT lower(hex(o.wire_group_id)),o.local_name,o.mls_epoch,o.membership_epoch,
                    p.agent_id,m.peer_id,m.role='creator',
                    coalesce(r.role,'member'),coalesce(r.muted,0),
                    coalesce(gp.permissions,3)
             FROM owned o JOIN group_members m ON m.group_id=o.group_id AND m.state='active'
             JOIN peers p ON p.peer_id=m.peer_id
             LEFT JOIN group_access_members r
               ON r.group_id=o.group_id AND r.peer_id=m.peer_id
             LEFT JOIN group_access_policies gp ON gp.group_id=o.group_id
             ORDER BY o.created_at_ms DESC,o.group_id,m.role,m.peer_id"
        ).map_err(database_error)?;
        let mut rows = statement
            .query(rusqlite::params![
                bs58::encode(device.as_bytes()).into_string(),
                VIEW_LIMIT as i64
            ])
            .map_err(database_error)?;
        let mut rooms: Vec<AdminRoom> = Vec::new();
        while let Some(row) = rows.next().map_err(database_error)? {
            let wire: String = row.get(0).map_err(database_error)?;
            if rooms.last().is_none_or(|r| r.room != wire) {
                rooms.push(AdminRoom {
                    room: wire,
                    name: row.get(1).map_err(database_error)?,
                    epoch: super::unsigned(row.get(2).map_err(database_error)?)?,
                    membership_epoch: super::unsigned(row.get(3).map_err(database_error)?)?,
                    members: vec![],
                });
            }
            let members = &mut rooms.last_mut().ok_or(AslError::InvalidDatabase)?.members;
            if members.len() >= asl_types::protocol::MAX_GROUP_MEMBERS {
                return Err(AslError::InvalidDatabase);
            }
            let creator: bool = row.get(6).map_err(database_error)?;
            let role: String = if creator {
                "owner".into()
            } else {
                row.get(7).map_err(database_error)?
            };
            let muted: bool = row.get::<_, i64>(8).map_err(database_error)? != 0;
            let permissions: u8 = u8::try_from(row.get::<_, i64>(9).map_err(database_error)?)
                .map_err(|_| AslError::InvalidDatabase)?;
            let admin = role == "admin";
            let can_send = !muted && (admin || role == "owner");
            members.push(AdminMember {
                agent: row.get(4).map_err(database_error)?,
                device: row.get(5).map_err(database_error)?,
                creator,
                role,
                muted,
                can_send_text: !muted
                    && (can_send
                        || permissions & asl_types::protocol::GROUP_ALLOW_MEMBER_TEXT != 0),
                can_send_files: !muted
                    && (can_send
                        || permissions & asl_types::protocol::GROUP_ALLOW_MEMBER_FILES != 0),
                can_invite: !muted
                    && (can_send
                        || permissions & asl_types::protocol::GROUP_ALLOW_MEMBER_INVITE != 0),
            });
        }
        Ok(rooms)
    }

    pub fn queue_group_admin(
        &mut self,
        agent: AgentId,
        device: &PeerId,
        request: AdminRequest,
        now: u64,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let old = read(&tx, now)?;
        if old.as_ref().is_some_and(AdminTicket::active) {
            return Err(AslError::QuotaExceeded);
        }
        let mut expires_ms = now.saturating_add(REQUEST_WINDOW_MS);
        if request != AdminRequest::Refresh {
            if !old.is_some_and(|t| t.outcome == AdminOutcome::Ready && t.owned_by(agent, device)) {
                return Err(AslError::PolicyVersionConflict);
            }
            let view = current_view(&tx, now)?
                .filter(|v| v.permits_selection(&request, now))
                .ok_or(AslError::PolicyVersionConflict)?;
            expires_ms = expires_ms.min(view.expires_ms);
        }
        tx.execute("DELETE FROM settings WHERE key=?1", [VIEW_KEY])
            .map_err(database_error)?;
        save(
            &tx,
            &AdminTicket {
                id: Id128(rand::random()),
                agent,
                device: bs58::encode(device.as_bytes()).into_string(),
                request,
                outcome: AdminOutcome::Queued,
                expires_ms,
            },
            now,
        )?;
        tx.commit().map_err(database_error)
    }

    pub fn claim_group_admin(
        &mut self,
        agent: AgentId,
        device: &PeerId,
        now: u64,
    ) -> Result<Option<AdminTicket>, AslError> {
        if !read(&self.connection, now)?.is_some_and(|t| t.outcome == AdminOutcome::Queued) {
            return Ok(None);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let Some(mut t) = read(&tx, now)?.filter(|t| t.outcome == AdminOutcome::Queued) else {
            return Ok(None);
        };
        let matched = t.owned_by(agent, device);
        t.outcome = if matched {
            AdminOutcome::Applying
        } else {
            AdminOutcome::Failed
        };
        save(&tx, &t, now)?;
        tx.commit().map_err(database_error)?;
        Ok(matched.then_some(t))
    }

    pub fn finish_group_admin(
        &mut self,
        ticket: &AdminTicket,
        outcome: AdminOutcome,
        view: Option<&AdminSnapshot>,
        now: u64,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let Some(mut t) =
            read(&tx, now)?.filter(|t| t.id == ticket.id && t.outcome == AdminOutcome::Applying)
        else {
            return Ok(());
        };
        t.outcome = outcome;
        if let Some(view) = view {
            write_setting(
                &tx,
                VIEW_KEY,
                &serde_json::to_string(view).map_err(|_| AslError::InvalidDatabase)?,
                sql_number(now)?,
            )?;
        }
        save(&tx, &t, now)?;
        tx.commit().map_err(database_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_admin_view_is_one_shot_and_bound_to_its_owner_and_deadline() {
        let home = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&home.path().join("state.sqlite3")).unwrap();
        let agent = AgentId([7; 32]);
        let device = super::super::tests::test_peer(1);
        let other = super::super::tests::test_peer(2);
        let refresh = |store: &mut Store, now| {
            store
                .queue_group_admin(agent, &device, AdminRequest::Refresh, now)
                .unwrap();
            let ticket = store
                .claim_group_admin(agent, &device, now)
                .unwrap()
                .unwrap();
            let view = AdminSnapshot {
                tag: "v".into(),
                rooms: vec![],
                peers: vec![],
                expires_ms: now + 10,
            };
            store
                .finish_group_admin(&ticket, AdminOutcome::Ready, Some(&view), now)
                .unwrap();
        };
        let create = || AdminRequest::Create { tag: "v".into() };
        refresh(&mut store, 10);
        assert!(
            store
                .local_group_admin_snapshot(agent, &other, 11)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .queue_group_admin(agent, &other, create(), 11)
                .is_err()
        );
        assert!(
            store
                .queue_group_admin(AgentId([8; 32]), &device, create(), 11)
                .is_err()
        );
        assert!(
            store
                .queue_group_admin(agent, &device, create(), 20)
                .is_err()
        );
        refresh(&mut store, 21);
        store
            .queue_group_admin(agent, &device, create(), 22)
            .unwrap();
        assert!(
            store
                .claim_group_admin(agent, &device, 31)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.local_group_admin_status(31).unwrap(),
            Some(AdminOutcome::Unconfirmed)
        );
        refresh(&mut store, 32);
        store
            .queue_group_admin(agent, &device, create(), 33)
            .unwrap();
        let ticket = store
            .claim_group_admin(agent, &device, 33)
            .unwrap()
            .unwrap();
        assert!(
            store
                .claim_group_admin(agent, &device, 34)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .queue_group_admin(agent, &device, AdminRequest::Refresh, 34)
                .is_err()
        );
        store
            .finish_group_admin(&ticket, AdminOutcome::Created, None, 34)
            .unwrap();
        assert!(
            store
                .queue_group_admin(agent, &device, create(), 34)
                .is_err()
        );
        store
            .queue_group_admin(agent, &device, AdminRequest::Refresh, 35)
            .unwrap();
        store
            .finish_group_admin(&ticket, AdminOutcome::Failed, None, 35)
            .unwrap();
        assert_eq!(
            store.local_group_admin_status(35).unwrap(),
            Some(AdminOutcome::Queued)
        );
    }
}
