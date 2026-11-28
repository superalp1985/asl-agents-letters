use std::time::{Duration, Instant};

use asl_store::open_store;
use asl_types::{error::AslError, record::RecordKind};

use super::{NetworkAdmissionStatus, Supervisor, fresh_id, unix_time_ms};
use crate::{contact_policy_sync, network::NetworkCommand};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const LOOKUP_INTERVAL: Duration = Duration::from_secs(60);
const PHASE_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Preparing([u8; 16]),
    Ready([u8; 16]),
    Submitting([u8; 16]),
}

struct Pending {
    phase: Phase,
    revision: u64,
    record: Vec<u8>,
    deadline: Instant,
}

pub(super) struct ContactPolicySyncRuntime {
    next_poll: Instant,
    next_lookup: Instant,
    lookup: Option<[u8; 16]>,
    retired_lookup: Option<[u8; 16]>,
    lookup_deadline: Instant,
    pending: Option<Pending>,
}

impl Default for ContactPolicySyncRuntime {
    fn default() -> Self {
        Self {
            next_poll: Instant::now(),
            next_lookup: Instant::now(),
            lookup: None,
            retired_lookup: None,
            lookup_deadline: Instant::now(),
            pending: None,
        }
    }
}

impl Supervisor {
    pub(super) fn reset_contact_policy_sync_transport(&mut self) {
        self.contact_policy_sync.pending = None;
        self.contact_policy_sync.lookup = None;
        self.contact_policy_sync.retired_lookup = None;
        self.contact_policy_sync.lookup_deadline = Instant::now();
        self.contact_policy_sync.next_poll = Instant::now();
        self.contact_policy_sync.next_lookup = Instant::now();
    }

    pub(super) fn poll_contact_policy_sync(
        &mut self,
        now: Instant,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if now < self.contact_policy_sync.next_poll {
            return Ok(());
        }
        self.contact_policy_sync.next_poll = now + POLL_INTERVAL;
        let active = self.net.is_running()
            && self.network_admission_status == NetworkAdmissionStatus::Active;
        if !active {
            self.contact_policy_sync.pending = None;
            self.contact_policy_sync.lookup = None;
            return Ok(());
        }
        let store = open_store(&self.state_database)?;
        if !store.contact_policy_sync_authorized()? {
            self.contact_policy_sync.pending = None;
            self.contact_policy_sync.lookup = None;
            return Ok(());
        }
        if self.contact_policy_sync.lookup.is_some()
            && now >= self.contact_policy_sync.lookup_deadline
        {
            self.contact_policy_sync.retired_lookup = self.contact_policy_sync.lookup;
            self.contact_policy_sync.lookup = None;
            self.contact_policy_sync.next_lookup = now + LOOKUP_INTERVAL;
        }
        if let Some(pending) = self.contact_policy_sync.pending.as_ref()
            && now >= pending.deadline
        {
            let id = match pending.phase {
                Phase::Preparing(id) | Phase::Ready(id) | Phase::Submitting(id) => id,
            };
            let revision = pending.revision;
            let receipt = fresh_id()?;
            self.send_network_command(NetworkCommand::CancelContactPolicy {
                operation_id: id,
                receipt_id: receipt,
            })?;
            self.contact_policy_sync.pending = None;
            let _ = contact_policy_sync::note_failure_for_revision(&store, revision, now_ms);
        }
        if self.contact_policy_sync.lookup.is_none() && now >= self.contact_policy_sync.next_lookup
        {
            let id = fresh_id()?;
            let key = asl_net::dht::identity_record_key(
                self.agent_identity.agent_id(),
                RecordKind::ContactPolicy,
            )?
            .as_ref()
            .try_into()
            .map_err(|_| AslError::InvalidMessage)?;
            self.send_network_command(NetworkCommand::LookupDhtRecord {
                operation_id: id,
                key,
            })?;
            self.contact_policy_sync.lookup = Some(id);
            self.contact_policy_sync.lookup_deadline = now + PHASE_TIMEOUT;
            self.contact_policy_sync.next_lookup = now + LOOKUP_INTERVAL;
        }
        let ready = self
            .contact_policy_sync
            .pending
            .as_ref()
            .and_then(|pending| {
                if let Phase::Ready(id) = pending.phase {
                    Some((id, pending.record.clone()))
                } else {
                    None
                }
            });
        if let Some((id, record)) = ready {
            self.send_network_command(NetworkCommand::PublishContactPolicy {
                operation_id: id,
                value: record,
            })?;
            if let Some(pending) = self.contact_policy_sync.pending.as_mut() {
                pending.phase = Phase::Submitting(id);
                pending.deadline = now + PHASE_TIMEOUT;
            }
            return Ok(());
        }
        let Some(prepared) = contact_policy_sync::due(&self.agent_identity, &store, now_ms)? else {
            return Ok(());
        };
        let id = fresh_id()?;
        self.send_network_command(NetworkCommand::PrepareContactPolicy {
            operation_id: id,
            agent: self.agent_identity.agent_id(),
        })?;
        self.contact_policy_sync.pending = Some(Pending {
            phase: Phase::Preparing(id),
            revision: prepared.revision,
            record: prepared.record,
            deadline: now + PHASE_TIMEOUT,
        });
        Ok(())
    }

    pub(super) fn handle_contact_policy_sync_response(
        &mut self,
        operation_id: [u8; 16],
        ok: bool,
        now: Instant,
    ) -> bool {
        if self.contact_policy_sync.lookup == Some(operation_id) {
            self.contact_policy_sync.lookup = None;
            self.contact_policy_sync.lookup_deadline = now;
            if !ok {
                self.contact_policy_sync.next_lookup = now + LOOKUP_INTERVAL;
            }
            return true;
        }
        if self.contact_policy_sync.retired_lookup == Some(operation_id) {
            self.contact_policy_sync.retired_lookup = None;
            return true;
        }
        let Some(pending) = self.contact_policy_sync.pending.as_mut() else {
            return false;
        };
        let id = match pending.phase {
            Phase::Preparing(id) | Phase::Ready(id) | Phase::Submitting(id) => id,
        };
        let revision = pending.revision;
        if id != operation_id {
            return false;
        }
        if !ok {
            let store = open_store(&self.state_database).ok();
            if let Some(store) = store {
                let _ = contact_policy_sync::note_failure_for_revision(
                    &store,
                    revision,
                    unix_time_ms().unwrap_or_default(),
                );
            }
            self.contact_policy_sync.pending = None;
            return true;
        }
        match pending.phase {
            Phase::Preparing(_) => {
                pending.phase = Phase::Ready(id);
                pending.deadline = now + PHASE_TIMEOUT;
            }
            Phase::Submitting(_) => {
                let store = open_store(&self.state_database).ok();
                if let Some(store) = store {
                    let _ = contact_policy_sync::note_success_for_revision(
                        &store,
                        revision,
                        unix_time_ms().unwrap_or_default(),
                    );
                }
                self.contact_policy_sync.pending = None;
                self.contact_policy_sync.next_poll = now;
            }
            Phase::Ready(_) => {}
        }
        true
    }

    pub(super) fn observe_contact_policy_record(
        &mut self,
        agent_id: asl_types::ids::AgentId,
        kind: RecordKind,
        record: &[u8],
        now_ms: u64,
    ) {
        if kind != RecordKind::ContactPolicy || agent_id != self.agent_identity.agent_id() {
            return;
        }
        let Ok(store) = open_store(&self.state_database) else {
            return;
        };
        if contact_policy_sync::import(&self.agent_identity, &store, record, now_ms).is_ok() {
            self.contact_policy_sync.next_poll = Instant::now();
        }
    }
}
