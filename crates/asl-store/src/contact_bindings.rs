use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    record::{DeviceDirectory, short_code},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, chain::agent_text, database_error};

const MAX_ACTION_BATCH: i64 = 32;
const MAX_ACTION_HISTORY: i64 = 256;
const MAX_PENDING_ACTIONS: i64 = 64;
const MAX_BINDING_CANDIDATES: i64 = 200;
const MAX_PEER_ID_BASE58_BYTES: usize = 175;

impl Store {
    /// Core supplies a current chain-verified directory. Preserve the existing
    /// AgentId binding and only replace an explicitly revoked device.
    pub fn rebind_verified_contact_device(
        &self,
        directory: &DeviceDirectory,
        now_ms: u64,
    ) -> Result<Option<(String, String)>, AslError> {
        let mut active = directory
            .devices
            .iter()
            .filter(|device| device.issued_at_ms <= now_ms && now_ms < device.expires_at_ms);
        let Some(device) = active.next() else {
            return Ok(None);
        };
        if active.next().is_some() || directory.revoked_serials.is_empty() {
            return Ok(None);
        }
        let previous: Option<(String, i64)> = self
            .connection
            .query_row(
                "SELECT b.peer_id,d.certificate_serial
             FROM contact_bindings b JOIN device_identities d ON d.peer_id=b.peer_id
             WHERE b.agent_id=?1 AND b.state='bound' AND d.agent_id=?2",
                params![
                    directory.agent_id.as_bytes(),
                    agent_text(directory.agent_id)
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((previous, serial)) = previous else {
            return Ok(None);
        };
        if !u64::try_from(serial).is_ok_and(|serial| directory.revoked_serials.contains(&serial)) {
            return Ok(None);
        }
        let replacement = bs58::encode(device.peer_id.as_bytes()).into_string();
        let changed = self
            .connection
            .execute(
                "UPDATE contact_bindings SET peer_id=?1,updated_at_ms=?2
             WHERE agent_id=?3 AND peer_id=?4 AND state='bound'",
                params![
                    replacement,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                    directory.agent_id.as_bytes(),
                    previous
                ],
            )
            .map_err(database_error)?;
        Ok((changed == 1).then_some((previous, replacement)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactBindingState {
    Bound,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactBindingActionKind {
    Lookup,
    Approve,
    Dismiss,
    Revoke,
    Forget,
    PublishCode,
    UnpublishCode,
}

impl ContactBindingActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Approve => "approve",
            Self::Dismiss => "dismiss",
            Self::Revoke => "revoke",
            Self::Forget => "forget",
            Self::PublishCode => "publish_code",
            Self::UnpublishCode => "unpublish_code",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactBindingAction {
    pub id: i64,
    pub kind: ContactBindingActionKind,
    pub code: Option<u64>,
    pub agent_id: Option<AgentId>,
    pub peer_id: Option<PeerId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactBinding {
    pub agent_id: AgentId,
    pub peer_id: Option<String>,
    pub state: ContactBindingState,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactBindingCandidate {
    pub agent_id: AgentId,
    pub peer_id: String,
    pub code: u64,
    pub first_seen_ms: i64,
    pub dismissed: bool,
}

impl Store {
    pub fn enqueue_contact_binding_action(
        &self,
        kind: ContactBindingActionKind,
        code: Option<u64>,
        agent_id: Option<AgentId>,
        peer_id: Option<&PeerId>,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if now_ms > i64::MAX as u64
            || !valid_action(kind, code, agent_id, peer_id.is_some())
            || code.is_some_and(|code| code >= 10_000_000_000_000_000)
        {
            return Err(AslError::InvalidMessage);
        }
        let pending: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM contact_binding_actions
                 WHERE state IN ('queued','working')",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if pending >= MAX_PENDING_ACTIONS {
            return Err(AslError::QuotaExceeded);
        }
        self.connection
            .execute(
                "INSERT INTO contact_binding_actions(
                    kind,code,agent_id,peer_id,requested_at_ms,state
                 ) VALUES (?1,?2,?3,?4,?5,'queued')",
                params![
                    kind.as_str(),
                    code.map(|value| value as i64),
                    agent_id.map(|value| value.0.to_vec()),
                    peer_id.map(|value| bs58::encode(value.as_bytes()).into_string()),
                    now_ms as i64,
                ],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn claim_contact_binding_actions(&mut self) -> Result<Vec<ContactBindingAction>, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let actions = {
            let mut statement = tx
                .prepare(
                    "SELECT action_id,kind,code,agent_id,peer_id
                     FROM contact_binding_actions
                     WHERE state='queued'
                     ORDER BY action_id
                     LIMIT ?1",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([MAX_ACTION_BATCH], |row| {
                    let action_id = row.get(0)?;
                    let kind: String = row.get(1)?;
                    let code: Option<i64> = row.get(2)?;
                    let agent_id: Option<Vec<u8>> = row.get(3)?;
                    let peer_id: Option<String> = row.get(4)?;
                    Ok((action_id, kind, code, agent_id, peer_id))
                })
                .map_err(database_error)?;
            rows.map(|row| {
                let (id, kind, code, agent, peer) = row.map_err(database_error)?;
                let peer_id = peer.map(|value| peer_id_from_base58(&value)).transpose()?;
                Ok(ContactBindingAction {
                    id,
                    kind: parse_action_kind(&kind)?,
                    code: code
                        .map(|value| u64::try_from(value).map_err(|_| AslError::InvalidDatabase))
                        .transpose()?,
                    agent_id: agent
                        .map(|value| -> Result<AgentId, AslError> {
                            Ok(AgentId(
                                value.try_into().map_err(|_| AslError::InvalidDatabase)?,
                            ))
                        })
                        .transpose()?,
                    peer_id,
                })
            })
            .collect::<Result<Vec<_>, AslError>>()?
        };
        for action in &actions {
            tx.execute(
                "UPDATE contact_binding_actions SET state='working'
                 WHERE action_id=?1 AND state='queued'",
                [action.id],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)?;
        Ok(actions)
    }

    pub fn finish_contact_binding_action(
        &self,
        action_id: i64,
        result: Result<&str, &str>,
    ) -> Result<(), AslError> {
        let (state, message) = match result {
            Ok(message) => ("complete", message),
            Err(message) => ("failed", message),
        };
        if message.len() > 48 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "UPDATE contact_binding_actions
                 SET state=?2,result=?3
                 WHERE action_id=?1 AND state='working'",
                params![action_id, state, message],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "DELETE FROM contact_binding_actions
                 WHERE action_id IN (
                    SELECT action_id FROM contact_binding_actions
                    WHERE state IN ('complete','failed')
                    ORDER BY action_id DESC LIMIT -1 OFFSET ?1
                 )",
                [MAX_ACTION_HISTORY],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn resume_contact_binding_actions(&self) -> Result<(), AslError> {
        self.connection
            .execute(
                "UPDATE contact_binding_actions SET state='queued'
                 WHERE state='working'",
                [],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn contact_binding_state(
        &self,
        agent_id: AgentId,
    ) -> Result<Option<ContactBindingState>, AslError> {
        self.connection
            .query_row(
                "SELECT state FROM contact_bindings WHERE agent_id=?1",
                [agent_id.as_bytes().as_slice()],
                |row| {
                    let state: String = row.get(0)?;
                    match state.as_str() {
                        "bound" => Ok(ContactBindingState::Bound),
                        "revoked" => Ok(ContactBindingState::Revoked),
                        _ => Err(rusqlite::Error::InvalidQuery),
                    }
                },
            )
            .optional()
            .map_err(database_error)
    }

    pub fn contact_bindings(&self) -> Result<Vec<ContactBinding>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT agent_id,peer_id,state,updated_at_ms
                 FROM contact_bindings ORDER BY updated_at_ms DESC,agent_id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                let agent: Vec<u8> = row.get(0)?;
                let state: String = row.get(2)?;
                Ok((
                    agent,
                    row.get::<_, Option<String>>(1)?,
                    state,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(database_error)?;
        rows.map(|row| {
            let (agent, peer_id, state, updated_at_ms) = row.map_err(database_error)?;
            Ok(ContactBinding {
                agent_id: AgentId(agent.try_into().map_err(|_| AslError::InvalidDatabase)?),
                peer_id,
                state: parse_binding_state(&state)?,
                updated_at_ms,
            })
        })
        .collect()
    }

    pub fn contact_binding_candidates(&self) -> Result<Vec<ContactBindingCandidate>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT agent_id,peer_id,code,first_seen_ms,state
                 FROM contact_binding_candidates
                 ORDER BY state,first_seen_ms DESC,agent_id,peer_id LIMIT 200",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                let agent: Vec<u8> = row.get(0)?;
                let code: i64 = row.get(2)?;
                Ok((
                    agent,
                    row.get::<_, String>(1)?,
                    code,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(database_error)?;
        rows.map(|row| {
            let (agent, peer_id, code, first_seen_ms, state) = row.map_err(database_error)?;
            Ok(ContactBindingCandidate {
                agent_id: AgentId(agent.try_into().map_err(|_| AslError::InvalidDatabase)?),
                peer_id,
                code: u64::try_from(code).map_err(|_| AslError::InvalidDatabase)?,
                first_seen_ms,
                dismissed: state == "dismissed",
            })
        })
        .collect()
    }

    pub fn record_contact_binding_candidate(
        &self,
        agent_id: AgentId,
        peer_id: &PeerId,
        code: u64,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if now_ms > i64::MAX as u64
            || short_code(agent_id) != code
            || self.contact_binding_state(agent_id)? == Some(ContactBindingState::Bound)
        {
            return Ok(false);
        }
        let peer = bs58::encode(peer_id.as_bytes()).into_string();
        let exists: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM contact_binding_candidates
                    WHERE agent_id=?1 AND peer_id=?2
                 )",
                params![agent_id.as_bytes().as_slice(), peer],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !exists {
            let count: i64 = self
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM contact_binding_candidates",
                    [],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if count >= MAX_BINDING_CANDIDATES {
                let oldest_dismissed: Option<(Vec<u8>, String)> = self
                    .connection
                    .query_row(
                        "SELECT agent_id,peer_id FROM contact_binding_candidates
                         WHERE state='dismissed' ORDER BY first_seen_ms,agent_id,peer_id LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(database_error)?;
                let Some((dismissed_agent, dismissed_peer)) = oldest_dismissed else {
                    return Ok(false);
                };
                self.connection
                    .execute(
                        "DELETE FROM contact_binding_candidates WHERE agent_id=?1 AND peer_id=?2",
                        params![dismissed_agent, dismissed_peer],
                    )
                    .map_err(database_error)?;
            }
        }
        self.connection
            .execute(
                "INSERT INTO contact_binding_candidates(agent_id,peer_id,code,first_seen_ms,state)
                 VALUES (?1,?2,?3,?4,'pending')
                 ON CONFLICT(agent_id,peer_id) DO UPDATE SET
                    code=excluded.code,first_seen_ms=excluded.first_seen_ms,state='pending'",
                params![
                    agent_id.as_bytes().as_slice(),
                    peer,
                    code as i64,
                    now_ms as i64
                ],
            )
            .map_err(database_error)?;
        Ok(true)
    }

    pub fn approve_contact_binding(
        &self,
        agent_id: AgentId,
        peer_id: &PeerId,
        code: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if now_ms > i64::MAX as u64 || short_code(agent_id) != code {
            return Err(AslError::InvalidMessage);
        }
        let peer = bs58::encode(peer_id.as_bytes()).into_string();
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let candidate: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM contact_binding_candidates
                    WHERE agent_id=?1 AND peer_id=?2 AND code=?3
                      AND state='pending'
                 )",
                params![agent_id.as_bytes().as_slice(), peer, code as i64],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !candidate {
            return Err(AslError::NotFound);
        }
        tx.execute(
            "INSERT INTO contact_bindings(agent_id,peer_id,state,updated_at_ms)
             VALUES (?1,?2,'bound',?3)
             ON CONFLICT(agent_id) DO UPDATE SET
                peer_id=excluded.peer_id,state='bound',updated_at_ms=excluded.updated_at_ms",
            params![agent_id.as_bytes().as_slice(), peer, now_ms as i64],
        )
        .map_err(database_error)?;
        tx.execute(
            "DELETE FROM contact_binding_candidates WHERE agent_id=?1 AND peer_id=?2",
            params![agent_id.as_bytes().as_slice(), peer],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(())
    }

    pub fn dismiss_contact_binding_candidate(
        &self,
        agent_id: AgentId,
        peer_id: &PeerId,
    ) -> Result<(), AslError> {
        let peer = bs58::encode(peer_id.as_bytes()).into_string();
        let changed = self
            .connection
            .execute(
                "UPDATE contact_binding_candidates SET state='dismissed'
                 WHERE agent_id=?1 AND peer_id=?2",
                params![agent_id.as_bytes().as_slice(), peer],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::NotFound);
        }
        Ok(())
    }

    pub fn grant_contact_access(
        &mut self,
        agent: AgentId,
        reviewed_device: &PeerId,
        bound_at: i64,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let text = agent_text(agent);
        let valid: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM contact_bindings b, identity_registry_states r
                 WHERE b.agent_id=?1 AND b.peer_id=?2 AND b.updated_at_ms=?3 AND b.state='bound'
                 AND r.agent_id=?4 AND r.status='active'
                 AND NOT EXISTS(SELECT 1 FROM local_agent_identity WHERE agent_id=r.agent_id))",
                params![
                    agent.as_bytes(),
                    bs58::encode(reviewed_device.as_bytes()).into_string(),
                    bound_at,
                    text
                ],
                |r| r.get(0),
            )
            .map_err(database_error)?;
        if !valid {
            return Err(AslError::PolicyDenied);
        }
        let changed = tx
            .execute(
                "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision)
                 SELECT ?1,?2,revision+1 FROM policy_state WHERE singleton=1
                 ON CONFLICT(agent_id) DO NOTHING",
                params![text, crate::current_time_ms()],
            )
            .map_err(database_error)?;
        if changed > 0 {
            crate::resources::bump_revision(&tx)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn remove_contact_access(&mut self, agent: AgentId) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        remove_membership(&tx, agent)?;
        tx.commit().map_err(database_error)
    }

    pub fn revoke_contact_binding(&self, agent_id: AgentId, now_ms: u64) -> Result<(), AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let changed = tx
            .execute(
                "UPDATE contact_bindings
             SET state='revoked',updated_at_ms=?2 WHERE agent_id=?1",
                params![agent_id.as_bytes().as_slice(), now_ms as i64],
            )
            .map_err(database_error)?;
        if changed == 0 {
            return Err(AslError::NotFound);
        }
        remove_membership(&tx, agent_id)?;
        tx.execute(
            "DELETE FROM paired_contacts WHERE agent_id=?1",
            [agent_id.as_bytes().as_slice()],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(())
    }

    pub fn forget_contact_binding(&self, agent_id: AgentId) -> Result<(), AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        tx.execute(
            "DELETE FROM contact_bindings WHERE agent_id=?1",
            [agent_id.as_bytes().as_slice()],
        )
        .map_err(database_error)?;
        tx.execute(
            "DELETE FROM contact_binding_candidates WHERE agent_id=?1",
            [agent_id.as_bytes().as_slice()],
        )
        .map_err(database_error)?;
        tx.execute(
            "DELETE FROM paired_contacts WHERE agent_id=?1",
            [agent_id.as_bytes().as_slice()],
        )
        .map_err(database_error)?;
        remove_membership(&tx, agent_id)?;
        tx.commit().map_err(database_error)?;
        Ok(())
    }

    pub fn is_contact_binding_revoked(&self, agent_id: AgentId) -> Result<bool, AslError> {
        Ok(self.contact_binding_state(agent_id)? == Some(ContactBindingState::Revoked))
    }

    pub fn revoked_contact_bindings(&self) -> Result<Vec<AgentId>, AslError> {
        Ok(self
            .contact_bindings()?
            .into_iter()
            .filter_map(|binding| {
                (binding.state == ContactBindingState::Revoked).then_some(binding.agent_id)
            })
            .collect())
    }

    pub fn binding_code_public(&self) -> Result<bool, AslError> {
        let value = self.get_setting("ui.binding_code_public.v1")?;
        match value.as_deref() {
            Some("true") => Ok(true),
            Some("false") | None => Ok(false),
            _ => Err(AslError::InvalidDatabase),
        }
    }

    pub fn set_binding_code_public(&self, enabled: bool, now_ms: u64) -> Result<(), AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        self.set_setting(
            "ui.binding_code_public.v1",
            if enabled { "true" } else { "false" },
            now_ms as i64,
        )
    }
}

fn remove_membership(tx: &rusqlite::Transaction<'_>, agent: AgentId) -> Result<(), AslError> {
    if tx
        .execute(
            "DELETE FROM authorized_contacts WHERE agent_id=?1",
            [agent_text(agent)],
        )
        .map_err(database_error)?
        != 0
    {
        crate::resources::bump_revision(tx)?;
    }
    Ok(())
}

fn valid_action(
    kind: ContactBindingActionKind,
    code: Option<u64>,
    agent_id: Option<AgentId>,
    has_peer: bool,
) -> bool {
    match kind {
        ContactBindingActionKind::Lookup => code.is_some() && !has_peer,
        ContactBindingActionKind::Approve | ContactBindingActionKind::Dismiss => {
            code.is_some() && agent_id.is_some() && has_peer
        }
        ContactBindingActionKind::Revoke | ContactBindingActionKind::Forget => {
            code.is_none() && agent_id.is_some() && !has_peer
        }
        ContactBindingActionKind::PublishCode | ContactBindingActionKind::UnpublishCode => {
            code.is_none() && agent_id.is_none() && !has_peer
        }
    }
}

fn parse_action_kind(value: &str) -> Result<ContactBindingActionKind, AslError> {
    match value {
        "lookup" => Ok(ContactBindingActionKind::Lookup),
        "approve" => Ok(ContactBindingActionKind::Approve),
        "dismiss" => Ok(ContactBindingActionKind::Dismiss),
        "revoke" => Ok(ContactBindingActionKind::Revoke),
        "forget" => Ok(ContactBindingActionKind::Forget),
        "publish_code" => Ok(ContactBindingActionKind::PublishCode),
        "unpublish_code" => Ok(ContactBindingActionKind::UnpublishCode),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn parse_binding_state(value: &str) -> Result<ContactBindingState, AslError> {
    match value {
        "bound" => Ok(ContactBindingState::Bound),
        "revoked" => Ok(ContactBindingState::Revoked),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn peer_id_from_base58(value: &str) -> Result<PeerId, AslError> {
    if value.is_empty() || value.len() > MAX_PEER_ID_BASE58_BYTES {
        return Err(AslError::InvalidDatabase);
    }
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::open_store(&directory.path().join("asl.sqlite3")).unwrap();
        (directory, store)
    }

    #[test]
    fn local_binding_approval_is_separate_from_contact_authorization() {
        let (_directory, store) = store();
        let agent = AgentId([41; 32]);
        let peer = peer(42);
        let code = short_code(agent);

        assert!(
            store
                .record_contact_binding_candidate(agent, &peer, code, 10)
                .unwrap()
        );
        store
            .approve_contact_binding(agent, &peer, code, 11)
            .unwrap();

        assert_eq!(
            store.contact_binding_state(agent).unwrap(),
            Some(ContactBindingState::Bound)
        );
        assert!(store.authorized_contacts().unwrap().is_empty());
        assert!(store.paired_contacts().unwrap().is_empty());
    }

    #[test]
    fn contact_access_requires_reviewed_binding_and_only_real_changes_advance_policy() {
        let (_dir, mut store) = store();
        let agent = AgentId([10; 32]);
        let device = peer(11);
        let code = short_code(agent);
        store
            .record_contact_binding_candidate(agent, &device, code, 10)
            .unwrap();
        store
            .approve_contact_binding(agent, &device, code, 11)
            .unwrap();
        let revision = store.policy_revision().unwrap();
        assert!(matches!(
            store.grant_contact_access(agent, &device, 11),
            Err(AslError::PolicyDenied)
        ));
        store
            .connection
            .execute_batch(
                "INSERT INTO chain_state_cache VALUES
            (1,zeroblob(20),zeroblob(32),1,zeroblob(32),zeroblob(32),zeroblob(32),x'',0)",
            )
            .unwrap();
        let text = agent_text(agent);
        store
            .connection
            .execute("INSERT INTO agents(agent_id) VALUES(?1)", [&text])
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO identity_registry_states VALUES
            (?1,1,zeroblob(20),zeroblob(32),1,'active',1,zeroblob(32),0)",
                [&text],
            )
            .unwrap();
        for (peer, at) in [(&peer(12), 11), (&device, 10)] {
            assert!(matches!(
                store.grant_contact_access(agent, peer, at),
                Err(AslError::PolicyDenied)
            ));
        }
        for _ in 0..2 {
            store.grant_contact_access(agent, &device, 11).unwrap();
        }
        assert_eq!(store.authorized_contacts().unwrap(), [agent]);
        assert_eq!(store.policy_revision().unwrap(), revision + 1);
        for _ in 0..2 {
            store.remove_contact_access(agent).unwrap();
        }
        assert_eq!(store.policy_revision().unwrap(), revision + 2);
        assert_eq!(
            store.contact_binding_state(agent).unwrap(),
            Some(ContactBindingState::Bound)
        );
        store.grant_contact_access(agent, &device, 11).unwrap();
        store.revoke_contact_binding(agent, 12).unwrap();
        assert!(store.authorized_contacts().unwrap().is_empty());
        assert_eq!(store.policy_revision().unwrap(), revision + 4);
        assert!(matches!(
            store.grant_contact_access(agent, &device, 11),
            Err(AslError::PolicyDenied)
        ));
    }

    #[test]
    fn queued_actions_are_bounded_and_peer_ids_are_decoded_canonically() {
        let (_directory, mut store) = store();
        let agent = AgentId([51; 32]);
        let peer = peer(52);

        store
            .enqueue_contact_binding_action(
                ContactBindingActionKind::Approve,
                Some(short_code(agent)),
                Some(agent),
                Some(&peer),
                20,
            )
            .unwrap();
        let actions = store.claim_contact_binding_actions().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].peer_id.as_ref(), Some(&peer));

        store
            .finish_contact_binding_action(actions[0].id, Ok("approved"))
            .unwrap();
        for code in 0..MAX_PENDING_ACTIONS as u64 {
            store
                .enqueue_contact_binding_action(
                    ContactBindingActionKind::Lookup,
                    Some(code),
                    None,
                    None,
                    21,
                )
                .unwrap();
        }
        assert!(
            store
                .enqueue_contact_binding_action(
                    ContactBindingActionKind::Lookup,
                    Some(MAX_PENDING_ACTIONS as u64),
                    None,
                    None,
                    21,
                )
                .is_err()
        );
    }

    #[test]
    fn exact_agent_lookup_preserves_the_full_target_id() {
        let (_directory, mut store) = store();
        let agent = AgentId([71; 32]);
        store
            .enqueue_contact_binding_action(
                ContactBindingActionKind::Lookup,
                Some(short_code(agent)),
                Some(agent),
                None,
                25,
            )
            .unwrap();
        let actions = store.claim_contact_binding_actions().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].kind, ContactBindingActionKind::Lookup);
        assert_eq!(actions[0].code, Some(short_code(agent)));
        assert_eq!(actions[0].agent_id, Some(agent));
    }

    #[test]
    fn revoke_and_forget_update_the_local_block_state() {
        let (_directory, store) = store();
        let agent = AgentId([61; 32]);
        let peer = peer(62);
        let code = short_code(agent);
        store
            .record_contact_binding_candidate(agent, &peer, code, 30)
            .unwrap();
        store
            .approve_contact_binding(agent, &peer, code, 31)
            .unwrap();

        store.revoke_contact_binding(agent, 32).unwrap();
        assert!(store.is_contact_binding_revoked(agent).unwrap());
        assert_eq!(store.revoked_contact_bindings().unwrap(), [agent]);

        store.forget_contact_binding(agent).unwrap();
        assert!(!store.is_contact_binding_revoked(agent).unwrap());
        assert!(store.contact_bindings().unwrap().is_empty());
    }
}
