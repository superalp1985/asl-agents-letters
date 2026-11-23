//! Local, short-lived decisions about binding an existing inbox to one live MCP session.
use asl_types::{error::AslError, ids::Id128};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{Store, database_error, read_setting, write_setting};

const KEY: &str = "mcp.host_inbox_request.v2";
const WINDOW_MS: u64 = 600_000;

#[derive(Serialize, Deserialize, PartialEq)]
enum Decision {
    Pending,
    Bind(Id128),
    Denied,
}

#[derive(Serialize, Deserialize)]
struct Request {
    id: Id128,
    expires: u64,
    decision: Decision,
}

fn read(db: &Connection, now: u64) -> Result<Option<Request>, AslError> {
    Ok(read_setting(db, KEY)?
        .map(|v| serde_json::from_str::<Request>(&v))
        .transpose()
        .map_err(|_| AslError::InvalidDatabase)?
        .filter(|r| now < r.expires))
}

fn save(db: &Connection, request: &Request, now: u64) -> Result<(), AslError> {
    write_setting(
        db,
        KEY,
        &serde_json::to_string(request).map_err(|_| AslError::InvalidDatabase)?,
        now.try_into().map_err(|_| AslError::InvalidMessage)?,
    )
}

pub(crate) fn pending_request(db: &Connection, now: u64) -> Result<Option<Id128>, AslError> {
    Ok(read(db, now)?
        .filter(|r| r.decision == Decision::Pending)
        .map(|r| r.id))
}

fn require_active_inbox(db: &Connection, grant: Id128) -> Result<(), AslError> {
    let active: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM write_grants WHERE write_grant_id=?1 AND kind='inbox' AND status='active')",
        [hex::encode(grant.0)], |row| row.get(0)).map_err(database_error)?;
    if !active {
        return Err(AslError::GrantRevoked);
    }
    Ok(())
}

impl Store {
    pub fn request_host_inbox(&self, id: Id128, now: u64) -> Result<(), AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Some(existing) = read(&tx, now)? {
            return if existing.id == id && existing.decision == Decision::Pending {
                Ok(())
            } else {
                Err(AslError::QuotaExceeded)
            };
        }
        let expires = now.checked_add(WINDOW_MS).ok_or(AslError::InvalidMessage)?;
        save(
            &tx,
            &Request {
                id,
                expires,
                decision: Decision::Pending,
            },
            now,
        )?;
        tx.commit().map_err(database_error)
    }

    pub fn decide_host_inbox(
        &self,
        id: Id128,
        grant: Option<Id128>,
        now: u64,
    ) -> Result<(), AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut request = read(&tx, now)?
            .filter(|r| r.id == id && r.decision == Decision::Pending)
            .ok_or(AslError::NotFound)?;
        request.decision = match grant {
            Some(grant) => {
                require_active_inbox(&tx, grant)?;
                Decision::Bind(grant)
            }
            None => Decision::Denied,
        };
        save(&tx, &request, now)?;
        tx.commit().map_err(database_error)
    }

    pub fn host_inbox_decision(&self, id: Id128, now: u64) -> Result<Option<Id128>, AslError> {
        let request = read(&self.connection, now)?
            .filter(|r| r.id == id)
            .ok_or(AslError::ExpiredMessage)?;
        match request.decision {
            Decision::Pending => Ok(None),
            Decision::Bind(grant) => {
                require_active_inbox(&self.connection, grant)?;
                Ok(Some(grant))
            }
            Decision::Denied => Err(AslError::PolicyDenied),
        }
    }
}
