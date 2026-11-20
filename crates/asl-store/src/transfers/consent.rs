//! Local decisions for direct downloads. Nothing in this module is a wire command.

use super::*;
use rusqlite::Connection;

const MODE: &str = "transfer_approval.download_mode";
const TIMEOUT: &str = "transfer_approval.request_timeout_seconds";
const MAX_PROMPTS: i64 = 32;
const MAX_CANDIDATES: usize = 64;

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
                    c.destination_filename,c.download_size,c.source_peers_json,c.expires_at_ms,c.state
             FROM transfer_consents c JOIN write_grants w ON w.write_grant_id=c.destination_write_grant_id
             WHERE c.direction='download' AND c.group_id IS NULL AND c.destination_filename IS NOT NULL
               AND c.state IN ('pending','approved') AND c.expires_at_ms>?1
               AND w.kind='inbox' AND w.status='active' AND w.epoch=c.grant_epoch
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
             WHERE approval_id=?1 AND direction='download' AND group_id IS NULL
               AND destination_filename IS NOT NULL AND expires_at_ms>?3
               AND (state='pending' OR (state='approved' AND ?2='denied'))
               AND EXISTS(SELECT 1 FROM write_grants w WHERE w.write_grant_id=destination_write_grant_id
                          AND w.status='active' AND w.kind='inbox' AND w.epoch=grant_epoch)",
            params![hex::encode(id.0), state, current_time_ms()]
        ).map_err(database_error)?;
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
}

impl<'a> ConsentBinding<'a> {
    pub(super) fn new(
        grant: &'a str,
        epoch: i64,
        content: &'a str,
        filename: &'a str,
        bytes: i64,
        sources: &[String],
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
             WHERE direction='download' AND group_id IS NULL AND destination_write_grant_id=?1
               AND grant_epoch=?2 AND content_id=?3 AND destination_filename=?4
               AND download_size=?5 AND source_peers_json=?6 AND expires_at_ms>?7",
                params![
                    self.grant,
                    self.epoch,
                    self.content,
                    self.filename,
                    self.bytes,
                    self.sources_json,
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
            "DELETE FROM transfer_consents WHERE direction='download' AND group_id IS NULL
             AND destination_filename IS NOT NULL AND expires_at_ms<=?1",
            [now],
        )
        .map_err(database_error)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM transfer_consents WHERE direction='download' AND group_id IS NULL
             AND destination_filename IS NOT NULL", [], |row| row.get(0)
        ).map_err(database_error)?;
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
               destination_filename,download_size,source_peers_json)
             VALUES (?1,?2,'download',?3,?4,?5,'pending',?6,?7,?8,?9,?10)",
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
                self.sources_json
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
