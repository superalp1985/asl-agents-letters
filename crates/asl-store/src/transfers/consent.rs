//! Local decisions for direct and group-scoped downloads.

use super::*;
use crate::chain::agent_text;
use asl_types::ids::AgentId;
use rusqlite::Connection;

const MODE: &str = "transfer_approval.download_mode";
const UPLOAD_MODE: &str = "transfer_approval.upload_mode";
const TIMEOUT: &str = "transfer_approval.request_timeout_seconds";
const MAX_PROMPTS: i64 = 32;
const MAX_CANDIDATES: usize = 64;
const UPLOAD_PROMPT_WINDOW_MS: i64 = 86_400_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadMode {
    Ask,
    Automatic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadBinding {
    pub source_grant_id: Id128,
    pub grant_epoch: u64,
    pub content_id: Hash32,
    pub target_agent_id: Option<AgentId>,
    pub target_peer_id: PeerId,
    pub group: Option<GroupTransferBinding>,
    pub file_size: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum UploadAdmission {
    Allowed(Option<Id128>),
    Pending {
        approval_id: Id128,
        expires_at_ms: u64,
    },
    Denied,
}

#[derive(Debug, Eq, PartialEq)]
pub struct UploadConsent {
    pub approval_id: Id128,
    pub content_id: Hash32,
    pub source_grant_id: Id128,
    pub target_agent_id: Option<AgentId>,
    pub target_peer_id: PeerId,
    pub group: Option<GroupTransferBinding>,
    pub filename: String,
    pub file_size: u64,
    pub expires_at_ms: i64,
    pub approved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DownloadMode {
    Ask,
    Automatic,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DownloadStart {
    Pending {
        approval_id: Id128,
        transfer_id: TransferId,
    },
    Started(DownloadInfo),
}

impl DownloadStart {
    pub(super) fn started(self) -> Result<DownloadInfo, AslError> {
        match self {
            Self::Started(info) => Ok(info),
            Self::Pending { .. } => Err(AslError::PolicyDenied),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DownloadConsent {
    pub approval_id: Id128,
    pub content_id: Hash32,
    pub write_grant_id: Id128,
    pub group: Option<GroupTransferBinding>,
    pub destination_path: PathBuf,
    pub file_size: u64,
    pub sources: Vec<PeerId>,
    pub expires_at_ms: i64,
    pub approved: bool,
}

impl DownloadBroker {
    pub fn download_mode(&self) -> Result<DownloadMode, AslError> {
        self.store.download_mode()
    }

    pub fn set_download_mode(&self, mode: DownloadMode) -> Result<(), AslError> {
        self.store.set_download_mode(mode)
    }

    pub fn download_consents(&self) -> Result<Vec<DownloadConsent>, AslError> {
        self.store.download_consents()
    }

    pub fn decide_download(&mut self, id: Id128, approve: bool) -> Result<(), AslError> {
        self.store.decide_download(id, approve)
    }
}

// A local control panel must not open a second broker and recover live transfers.
impl Store {
    pub fn download_mode(&self) -> Result<DownloadMode, AslError> {
        mode(&self.connection)
    }

    pub fn set_download_mode(&self, mode: DownloadMode) -> Result<(), AslError> {
        let value = match mode {
            DownloadMode::Ask => r#""ask""#,
            DownloadMode::Automatic => r#""automatic""#,
        };
        self.set_setting(MODE, value, current_time_ms())
    }

    /// Includes approved items awaiting their matching request after a restart.
    pub fn download_consents(&self) -> Result<Vec<DownloadConsent>, AslError> {
        let mut statement = self.connection.prepare(
            "SELECT c.approval_id,c.content_id,c.destination_write_grant_id,w.root_path,
                    c.destination_filename,c.download_size,c.source_peers_json,c.expires_at_ms,c.state,
                    c.group_id,c.group_epoch
             FROM transfer_consents c JOIN write_grants w ON w.write_grant_id=c.destination_write_grant_id
             LEFT JOIN asl_groups g ON g.group_id=c.group_id
             WHERE c.direction='download' AND c.destination_filename IS NOT NULL
               AND c.state IN ('pending','approved') AND c.expires_at_ms>?1
               AND w.kind='inbox' AND w.status='active' AND w.epoch=c.grant_epoch
               AND ((c.group_id IS NULL AND c.group_epoch IS NULL)
                    OR (g.state='active' AND g.membership_epoch=c.group_epoch))
             ORDER BY c.created_at_ms,c.approval_id LIMIT ?2"
        ).map_err(database_error)?;
        let mut rows = statement
            .query(params![current_time_ms(), MAX_PROMPTS])
            .map_err(database_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(database_error)? {
            let text = |column| row.get::<_, String>(column).map_err(database_error);
            let peers: Vec<String> =
                serde_json::from_str(&text(6)?).map_err(|_| AslError::InvalidDatabase)?;
            result.push(DownloadConsent {
                approval_id: parse_id(&text(0)?)?,
                content_id: Hash32(parse_hash(&text(1)?)?),
                write_grant_id: parse_id(&text(2)?)?,
                group: group_binding(
                    row.get::<_, Option<String>>(9).map_err(database_error)?,
                    row.get::<_, Option<i64>>(10).map_err(database_error)?,
                )?,
                destination_path: Path::new(&text(3)?)
                    .join(normalize_filename(Path::new(&text(4)?))?),
                file_size: u64::try_from(row.get::<_, i64>(5).map_err(database_error)?)
                    .map_err(|_| AslError::InvalidDatabase)?,
                sources: peers
                    .iter()
                    .map(|s| parse_peer(s))
                    .collect::<Result<_, _>>()?,
                expires_at_ms: row.get(7).map_err(database_error)?,
                approved: text(8)? == "approved",
            });
        }
        Ok(result)
    }

    /// Human decision only. Approval itself does not create a task or a file.
    pub fn decide_download(&mut self, id: Id128, approve: bool) -> Result<(), AslError> {
        let state = if approve { "approved" } else { "denied" };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = tx.execute(
            "UPDATE transfer_consents SET state=?2,decided_at_ms=?3
             WHERE approval_id=?1 AND direction='download'
               AND destination_filename IS NOT NULL AND expires_at_ms>?3
               AND (state='pending' OR (state='approved' AND ?2='denied'))
               AND EXISTS(SELECT 1 FROM write_grants w WHERE w.write_grant_id=destination_write_grant_id
                          AND w.status='active' AND w.kind='inbox' AND w.epoch=grant_epoch)
               AND (group_id IS NULL OR EXISTS(
                   SELECT 1 FROM asl_groups g
                   WHERE g.group_id=transfer_consents.group_id
                     AND g.state='active' AND g.membership_epoch=transfer_consents.group_epoch))",
            params![hex::encode(id.0), state, current_time_ms()]
        ).map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::PolicyDenied);
        }
        tx.commit().map_err(database_error)
    }

    pub fn upload_mode(&self) -> Result<UploadMode, AslError> {
        let value: Option<String> = self
            .connection
            .query_row(
                "SELECT value_json FROM settings WHERE key=?1",
                [UPLOAD_MODE],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        match value
            .as_deref()
            .map(serde_json::from_str::<String>)
            .transpose()
            .map_err(|_| AslError::InvalidPolicyState)?
            .as_deref()
        {
            None | Some("automatic") => Ok(UploadMode::Automatic),
            Some("ask") => Ok(UploadMode::Ask),
            _ => Err(AslError::InvalidPolicyState),
        }
    }

    pub fn set_upload_mode(&self, mode: UploadMode) -> Result<(), AslError> {
        let value = match mode {
            UploadMode::Ask => r#""ask""#,
            UploadMode::Automatic => r#""automatic""#,
        };
        self.set_setting(UPLOAD_MODE, value, current_time_ms())
    }

    pub fn upload_consents(&self) -> Result<Vec<UploadConsent>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT c.approval_id,c.content_id,c.source_grant_id,c.target_agent_id,
                    c.target_peer_id,c.group_id,c.group_epoch,c.upload_filename,c.upload_size,
                    c.expires_at_ms,c.state
             FROM transfer_consents c
             JOIN grants g ON g.grant_id=c.source_grant_id
             JOIN resources r ON r.grant_id=c.source_grant_id
                            AND r.content_id=c.content_id
                            AND r.source_grant_epoch=c.grant_epoch
             JOIN snapshots s ON s.content_id=c.content_id
             LEFT JOIN asl_groups group_state ON group_state.group_id=c.group_id
             WHERE c.direction='upload' AND c.state IN ('pending','approved')
               AND c.expires_at_ms>?1 AND c.target_peer_id IS NOT NULL
               AND c.upload_filename IS NOT NULL AND c.upload_size IS NOT NULL
               AND g.status='active' AND g.epoch=c.grant_epoch
               AND r.active=1 AND r.origin='local' AND s.state='ready'
               AND EXISTS(SELECT 1 FROM device_identities d
                          WHERE d.peer_id=c.target_peer_id AND d.revoked_at_ms IS NULL
                            AND d.certificate_expires_ms>?1
                            AND (c.target_agent_id IS NULL OR d.agent_id=c.target_agent_id))
               AND (c.group_id IS NULL OR
                    (group_state.state='active'
                     AND group_state.membership_epoch=c.group_epoch
                     AND EXISTS(SELECT 1 FROM group_members member
                                WHERE member.group_id=c.group_id
                                  AND member.peer_id=c.target_peer_id
                                  AND member.state='active')))
             ORDER BY c.created_at_ms,c.approval_id LIMIT ?2",
            )
            .map_err(database_error)?;
        let mut rows = statement
            .query(params![current_time_ms(), MAX_PROMPTS])
            .map_err(database_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(database_error)? {
            let text = |column| row.get::<_, String>(column).map_err(database_error);
            let target_agent_id = row
                .get::<_, Option<String>>(3)
                .map_err(database_error)?
                .map(|text| parse_agent(&text))
                .transpose()?;
            let group = group_binding(
                row.get::<_, Option<String>>(5).map_err(database_error)?,
                row.get::<_, Option<i64>>(6).map_err(database_error)?,
            )?
            .map(|binding| GroupTransferBinding {
                group_id: binding.group_id,
                membership_epoch: binding.membership_epoch,
            });
            result.push(UploadConsent {
                approval_id: parse_id(&text(0)?)?,
                content_id: Hash32(parse_hash(&text(1)?)?),
                source_grant_id: parse_id(&text(2)?)?,
                target_agent_id,
                target_peer_id: parse_peer(&text(4)?)?,
                group,
                filename: text(7)?,
                file_size: u64::try_from(row.get::<_, i64>(8).map_err(database_error)?)
                    .map_err(|_| AslError::InvalidDatabase)?,
                expires_at_ms: row.get(9).map_err(database_error)?,
                approved: text(10)? == "approved",
            });
        }
        Ok(result)
    }

    pub fn decide_upload(&mut self, id: Id128, approve: bool) -> Result<(), AslError> {
        let state = if approve { "approved" } else { "denied" };
        let now = current_time_ms();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = tx
            .execute(
                "UPDATE transfer_consents SET state=?2,decided_at_ms=?3
                 WHERE approval_id=?1 AND direction='upload' AND target_peer_id IS NOT NULL
                   AND upload_filename IS NOT NULL AND upload_size IS NOT NULL
                   AND expires_at_ms>?3
                   AND (state='pending' OR (state='approved' AND ?2='denied'))
                   AND EXISTS(SELECT 1 FROM grants g JOIN resources r ON r.grant_id=g.grant_id
                              JOIN snapshots s ON s.content_id=r.content_id
                              WHERE g.grant_id=transfer_consents.source_grant_id
                                AND g.status='active' AND g.epoch=transfer_consents.grant_epoch
                                AND r.content_id=transfer_consents.content_id
                                AND r.source_grant_epoch=g.epoch AND r.active=1
                                AND r.origin='local' AND s.state='ready')
                   AND EXISTS(SELECT 1 FROM device_identities d
                              WHERE d.peer_id=transfer_consents.target_peer_id
                                AND d.revoked_at_ms IS NULL AND d.certificate_expires_ms>?3
                                AND (transfer_consents.target_agent_id IS NULL
                                     OR d.agent_id=transfer_consents.target_agent_id))
                   AND (group_id IS NULL OR EXISTS(
                       SELECT 1 FROM asl_groups g JOIN group_members m ON m.group_id=g.group_id
                       WHERE g.group_id=transfer_consents.group_id AND g.state='active'
                         AND g.membership_epoch=transfer_consents.group_epoch
                         AND m.peer_id=transfer_consents.target_peer_id AND m.state='active'))",
                params![hex::encode(id.0), state, now],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::PolicyDenied);
        }
        tx.commit().map_err(database_error)
    }

    pub fn admit_upload(
        &self,
        binding: &UploadBinding,
        now_ms: u64,
    ) -> Result<UploadAdmission, AslError> {
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let grant = hex::encode(binding.source_grant_id.0);
        let epoch = i64::try_from(binding.grant_epoch).map_err(|_| AslError::InvalidMessage)?;
        let content = hex::encode(binding.content_id.0);
        let peer = peer_text(&binding.target_peer_id);
        let agent = binding.target_agent_id.map(agent_text);
        let group = binding
            .group
            .as_ref()
            .map(|group| {
                Ok::<_, AslError>((
                    hex::encode(group.group_id.0.as_bytes()),
                    i64::try_from(group.membership_epoch).map_err(|_| AslError::InvalidMessage)?,
                ))
            })
            .transpose()?;
        if binding.group.is_some() == binding.target_agent_id.is_some() {
            return Err(AslError::InvalidMessage);
        }
        let bytes = i64::try_from(binding.file_size).map_err(|_| AslError::QuotaExceeded)?;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let (source, source_size) = tx
            .query_row(
                "SELECT r.source_relative,s.file_size FROM grants g
                 JOIN resources r ON r.grant_id=g.grant_id
                 JOIN snapshots s ON s.content_id=r.content_id
                 WHERE g.grant_id=?1 AND g.status='active' AND g.epoch=?2
                   AND r.content_id=?3 AND r.source_grant_epoch=g.epoch
                   AND r.active=1 AND r.origin='local' AND s.state='ready'",
                params![grant, epoch, content],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::PolicyDenied)?;
        if source_size != bytes {
            return Err(AslError::PolicyDenied);
        }
        let target_device_active: bool = match binding.target_agent_id {
            Some(agent_id) => tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM device_identities
                 WHERE peer_id=?1 AND agent_id=?2 AND revoked_at_ms IS NULL
                   AND certificate_expires_ms>?3)",
                params![peer, agent_text(agent_id), now],
                |row| row.get(0),
            ),
            None => tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM device_identities
                 WHERE peer_id=?1 AND revoked_at_ms IS NULL
                   AND certificate_expires_ms>?2)",
                params![peer, now],
                |row| row.get(0),
            ),
        }
        .map_err(database_error)?;
        if !target_device_active {
            return Err(AslError::PolicyDenied);
        }
        if let Some((group_id, group_epoch)) = &group {
            let member: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM asl_groups g JOIN group_members m
                     ON m.group_id=g.group_id WHERE g.group_id=?1 AND g.state='active'
                       AND g.membership_epoch=?2 AND m.peer_id=?3 AND m.state='active')",
                    params![group_id, group_epoch, peer],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if !member {
                return Err(AslError::PolicyDenied);
            }
        }
        let existing = tx
            .query_row(
                "SELECT approval_id,state,expires_at_ms FROM transfer_consents
                 WHERE direction='upload' AND source_grant_id=?1 AND grant_epoch=?2
                   AND content_id=?3 AND target_peer_id=?4
                   AND target_agent_id IS ?5 AND group_id IS ?6 AND group_epoch IS ?7
                 ORDER BY created_at_ms DESC LIMIT 1",
                params![
                    grant,
                    epoch,
                    content,
                    peer,
                    agent,
                    group.as_ref().map(|binding| binding.0.as_str()),
                    group.as_ref().map(|binding| binding.1)
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        if let Some((approval, state, expires)) = existing {
            let id = parse_id(&approval)?;
            if expires > now {
                let admission = match state.as_str() {
                    "approved" => UploadAdmission::Allowed(Some(id)),
                    "pending" => UploadAdmission::Pending {
                        approval_id: id,
                        expires_at_ms: u64::try_from(expires)
                            .map_err(|_| AslError::InvalidDatabase)?,
                    },
                    _ => UploadAdmission::Denied,
                };
                tx.commit().map_err(database_error)?;
                return Ok(admission);
            }
            if state == "denied" || self.upload_mode()? == UploadMode::Automatic {
                tx.commit().map_err(database_error)?;
                return Ok(UploadAdmission::Denied);
            }
        }
        if self.upload_mode()? == UploadMode::Automatic {
            tx.commit().map_err(database_error)?;
            return Ok(UploadAdmission::Allowed(None));
        }
        tx.execute(
            "DELETE FROM transfer_consents WHERE direction='upload'
             AND expires_at_ms<=?1 AND created_at_ms<=?2",
            params![now, now.saturating_sub(UPLOAD_PROMPT_WINDOW_MS)],
        )
        .map_err(database_error)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM transfer_consents WHERE direction='upload'
                 AND created_at_ms>?1",
                [now.saturating_sub(UPLOAD_PROMPT_WINDOW_MS)],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if count >= MAX_PROMPTS {
            return Err(AslError::QuotaExceeded);
        }
        let seconds = setting(&tx, TIMEOUT, 300)?;
        if !(1..=300).contains(&seconds) {
            return Err(AslError::InvalidPolicyState);
        }
        let filename = Path::new(&source)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(AslError::InvalidDatabase)?;
        let approval = random_id();
        let expires = now.saturating_add(seconds * 1_000);
        tx.execute(
            "INSERT INTO transfer_consents(
                 approval_id,transfer_id,direction,content_id,source_grant_id,
                 target_agent_id,target_peer_id,group_id,group_epoch,grant_epoch,state,
                 created_at_ms,expires_at_ms,upload_filename,upload_size)
             VALUES (?1,?2,'upload',?3,?4,?5,?6,?7,?8,?9,'pending',?10,?11,?12,?13)",
            params![
                hex::encode(approval.0),
                hex::encode(random_id().0),
                content,
                grant,
                agent,
                peer,
                group.as_ref().map(|binding| binding.0.as_str()),
                group.as_ref().map(|binding| binding.1),
                epoch,
                now,
                expires,
                filename,
                bytes,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(UploadAdmission::Pending {
            approval_id: approval,
            expires_at_ms: u64::try_from(expires).map_err(|_| AslError::InvalidDatabase)?,
        })
    }

    pub fn consume_upload_approval(&self, id: Id128, now_ms: u64) -> Result<(), AslError> {
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = tx
            .execute(
                "UPDATE transfer_consents SET state='consumed'
                 WHERE approval_id=?1 AND direction='upload' AND state='approved'
                   AND target_peer_id IS NOT NULL AND upload_filename IS NOT NULL
                   AND upload_size IS NOT NULL
                   AND expires_at_ms>?2
                   AND EXISTS(SELECT 1 FROM grants g JOIN resources r ON r.grant_id=g.grant_id
                              JOIN snapshots s ON s.content_id=r.content_id
                              WHERE g.grant_id=transfer_consents.source_grant_id
                                AND g.status='active' AND g.epoch=transfer_consents.grant_epoch
                                AND r.content_id=transfer_consents.content_id
                                AND r.source_grant_epoch=g.epoch AND r.active=1
                                AND r.origin='local' AND s.state='ready')
                   AND EXISTS(SELECT 1 FROM device_identities d
                              WHERE d.peer_id=transfer_consents.target_peer_id
                                AND d.revoked_at_ms IS NULL AND d.certificate_expires_ms>?2
                                AND (transfer_consents.target_agent_id IS NULL
                                     OR d.agent_id=transfer_consents.target_agent_id))
                   AND (group_id IS NULL OR EXISTS(
                       SELECT 1 FROM asl_groups g JOIN group_members m ON m.group_id=g.group_id
                       WHERE g.group_id=transfer_consents.group_id AND g.state='active'
                         AND g.membership_epoch=transfer_consents.group_epoch
                         AND m.peer_id=transfer_consents.target_peer_id AND m.state='active'))",
                params![hex::encode(id.0), now],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::PolicyDenied);
        }
        tx.commit().map_err(database_error)
    }
}

fn mode(db: &Connection) -> Result<DownloadMode, AslError> {
    let value: Option<String> = db
        .query_row(
            "SELECT value_json FROM settings WHERE key=?1",
            [MODE],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    match value
        .as_deref()
        .map(serde_json::from_str::<String>)
        .transpose()
        .map_err(|_| AslError::InvalidPolicyState)?
        .as_deref()
    {
        None | Some("automatic") => Ok(DownloadMode::Automatic),
        Some("ask") => Ok(DownloadMode::Ask),
        _ => Err(AslError::InvalidPolicyState),
    }
}

fn parse_agent(text: &str) -> Result<AgentId, AslError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    Ok(AgentId(
        bytes.try_into().map_err(|_| AslError::InvalidDatabase)?,
    ))
}

pub(super) fn source_set(peers: &[PeerId]) -> Result<Vec<String>, AslError> {
    if peers.len() > MAX_CANDIDATES {
        return Err(AslError::QuotaExceeded);
    }
    let mut sources: Vec<_> = peers.iter().map(peer_text).collect();
    sources.sort_unstable();
    sources.dedup();
    Ok(sources)
}

pub(super) enum StartIntent {
    AutomaticOnly,
    MayPrompt,
    UseApproval(Id128),
}

pub(super) enum Admission {
    Pending {
        approval_id: Id128,
        transfer_id: TransferId,
    },
    Ready {
        transfer: TransferId,
        deadline: Option<i64>,
    },
}

pub(super) struct ConsentBinding<'a> {
    grant: &'a str,
    epoch: i64,
    content: &'a str,
    filename: &'a str,
    bytes: i64,
    sources_json: String,
    group_id: Option<String>,
    group_epoch: Option<i64>,
}

impl<'a> ConsentBinding<'a> {
    pub(super) fn new(
        grant: &'a str,
        epoch: i64,
        content: &'a str,
        filename: &'a str,
        bytes: i64,
        sources: &[String],
        group: Option<&super::GroupBindingText>,
    ) -> Result<Self, AslError> {
        let sources_json =
            serde_json::to_string(sources).map_err(|_| AslError::InvalidPolicyState)?;
        Ok(Self {
            grant,
            epoch,
            content,
            filename,
            bytes,
            sources_json,
            group_id: group.map(|group| group.id.clone()),
            group_epoch: group.map(|group| group.epoch),
        })
    }

    pub(super) fn admit(
        &self,
        tx: &Transaction<'_>,
        intent: StartIntent,
        now: i64,
    ) -> Result<Admission, AslError> {
        let existing = tx
            .query_row(
                "SELECT approval_id,transfer_id,state,expires_at_ms FROM transfer_consents
             WHERE direction='download' AND destination_write_grant_id=?1
               AND grant_epoch=?2 AND content_id=?3 AND destination_filename=?4
               AND download_size=?5 AND source_peers_json=?6 AND expires_at_ms>?9
               AND ((?7 IS NULL AND group_id IS NULL AND group_epoch IS NULL)
                    OR (group_id=?7 AND group_epoch=?8))",
                params![
                    self.grant,
                    self.epoch,
                    self.content,
                    self.filename,
                    self.bytes,
                    self.sources_json,
                    self.group_id,
                    self.group_epoch,
                    now
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        if let Some((approval, transfer, state, deadline)) = existing {
            let id = parse_id(&approval)?;
            return match intent {
                StartIntent::UseApproval(given) if given == id && state == "approved" => {
                    tx.execute(
                        "UPDATE transfer_consents SET state='consumed' WHERE approval_id=?1",
                        [&approval],
                    )
                    .map_err(database_error)?;
                    Ok(Admission::Ready {
                        transfer: parse_transfer(&transfer)?,
                        deadline: Some(deadline),
                    })
                }
                StartIntent::MayPrompt if matches!(state.as_str(), "pending" | "approved") => {
                    Ok(Admission::Pending {
                        approval_id: id,
                        transfer_id: parse_transfer(&transfer)?,
                    })
                }
                _ => Err(AslError::PolicyDenied),
            };
        }
        if matches!(intent, StartIntent::UseApproval(_)) {
            return Err(AslError::PolicyDenied);
        }
        let transfer = TransferId(random_id());
        if mode(tx)? == DownloadMode::Automatic {
            return Ok(Admission::Ready {
                transfer,
                deadline: None,
            });
        }
        if matches!(intent, StartIntent::AutomaticOnly) {
            return Err(AslError::PolicyDenied);
        }

        // Count decided items too: rapidly changing names or denying prompts does not refill the queue.
        tx.execute(
            "DELETE FROM transfer_consents WHERE direction='download'
             AND destination_filename IS NOT NULL AND expires_at_ms<=?1",
            [now],
        )
        .map_err(database_error)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM transfer_consents WHERE direction='download'
             AND destination_filename IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if count >= MAX_PROMPTS {
            return Err(AslError::QuotaExceeded);
        }
        let seconds = setting(tx, TIMEOUT, 300)?;
        if !(1..=300).contains(&seconds) {
            return Err(AslError::InvalidPolicyState);
        }
        let id = random_id();
        tx.execute(
            "INSERT INTO transfer_consents(approval_id,transfer_id,direction,content_id,
               destination_write_grant_id,grant_epoch,state,created_at_ms,expires_at_ms,
               destination_filename,download_size,source_peers_json,group_id,group_epoch)
             VALUES (?1,?2,'download',?3,?4,?5,'pending',?6,?7,?8,?9,?10,?11,?12)",
            params![
                hex::encode(id.0),
                hex::encode(transfer.0.0),
                self.content,
                self.grant,
                self.epoch,
                now,
                now.saturating_add(seconds * 1000),
                self.filename,
                self.bytes,
                self.sources_json,
                self.group_id,
                self.group_epoch
            ],
        )
        .map_err(database_error)?;
        Ok(Admission::Pending {
            approval_id: id,
            transfer_id: transfer,
        })
    }
}

pub(super) fn may_materialize(
    tx: &Transaction<'_>,
    deadline: Option<i64>,
) -> Result<bool, AslError> {
    match deadline {
        Some(deadline) => Ok(deadline > current_time_ms()),
        None => Ok(mode(tx)? == DownloadMode::Automatic),
    }
}
