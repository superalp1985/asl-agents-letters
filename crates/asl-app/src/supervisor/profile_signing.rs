use std::{
    path::Path,
    time::{Duration, Instant},
};

use asl_store::{
    Store, open_store,
    public_profile::{PROFILE_RENEWAL_MS, ProfilePublicationResult, ProfileSigningApproval},
};
use asl_types::error::AslError;

use super::{NetworkAdmissionStatus, Supervisor};
use crate::{ipc::IpcMessage, profile::fresh_id};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);
const PHASE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(PartialEq, Eq)]
enum Phase {
    Lookup,
    Ready,
    Submitted,
    Cancelling,
}

struct Pending {
    id: [u8; 16],
    approval: ProfileSigningApproval,
    phase: Phase,
    deadline: Instant,
}

pub(super) struct ProfileSigningRuntime {
    store: Store,
    next_poll: Instant,
    next_attempt: Instant,
    last_approval: Option<ProfileSigningApproval>,
    pending: Option<Pending>,
}

impl ProfileSigningRuntime {
    pub(super) fn open(database: &Path) -> Result<Self, AslError> {
        Ok(Self {
            store: open_store(database)?,
            next_poll: Instant::now(),
            next_attempt: Instant::now(),
            last_approval: None,
            pending: None,
        })
    }

    pub(super) fn reset_transport(&mut self) {
        self.pending = None;
        self.last_approval = None;
        self.next_poll = Instant::now();
    }

    pub(super) fn handle_response(&mut self, id: [u8; 16], ok: bool, now: Instant) -> bool {
        let Some(pending) = self.pending.as_mut().filter(|pending| pending.id == id) else {
            return false;
        };
        if pending.phase == Phase::Cancelling {
            return true;
        }
        if pending.phase == Phase::Lookup && ok {
            pending.phase = Phase::Ready;
            pending.deadline = now + PHASE_TIMEOUT;
            self.next_poll = now;
            return true;
        }
        if pending.phase == Phase::Ready {
            return true;
        }
        let pending = self.pending.take().unwrap();
        let outcome = if ok {
            ProfilePublicationResult::DhtAcknowledged
        } else {
            self.next_attempt = now + RETRY_INTERVAL;
            ProfilePublicationResult::NoAcknowledgment
        };
        let _ = self
            .store
            .observe_profile_publication(&pending.approval, outcome);
        true
    }
}

impl Supervisor {
    pub(super) fn poll_profile_signing(&mut self, now: Instant, now_ms: u64) {
        if now < self.profile_signing.next_poll || !self.net.is_running() {
            return;
        }
        self.profile_signing.next_poll = now + POLL_INTERVAL;
        if self.poll_profile_publication(now, now_ms).is_err()
            && let Some(pending) = self.profile_signing.pending.as_mut()
        {
            pending.phase = Phase::Cancelling;
        }
    }

    fn poll_profile_publication(&mut self, now: Instant, now_ms: u64) -> Result<(), AslError> {
        let active = self.network_admission_status == NetworkAdmissionStatus::Active;
        let runtime = &mut self.profile_signing;
        let approval = if active {
            runtime
                .store
                .current_public_profile(self.agent_identity.agent_id())?
        } else {
            None
        };
        if let Some(pending) = runtime.pending.as_mut() {
            if approval.as_ref() != Some(&pending.approval)
                || now >= pending.deadline
                || pending.phase == Phase::Cancelling
            {
                pending.phase = Phase::Cancelling;
                if self.net.try_send(&IpcMessage::CancelProfile {
                    operation_id: pending.id,
                })? {
                    let _ = runtime.store.observe_profile_publication(
                        &pending.approval,
                        ProfilePublicationResult::NoAcknowledgment,
                    );
                    runtime.pending = None;
                    runtime.next_attempt = now + RETRY_INTERVAL;
                }
                return Ok(());
            }
            if pending.phase != Phase::Ready {
                return Ok(());
            }
            let sequence = runtime
                .store
                .reserve_profile_sequence(self.agent_identity.agent_id())?;
            let value = self
                .admission
                .as_mut()
                .ok_or(AslError::InvalidIdentity)?
                .prepare_local_profile(&self.agent_identity, &pending.approval, sequence, now_ms)?
                .ok_or(AslError::InvalidPolicyState)?;
            if !runtime
                .store
                .observe_profile_candidate(&pending.approval, &value)?
            {
                pending.phase = Phase::Cancelling;
                return Ok(());
            }
            let message = IpcMessage::PublishProfile {
                operation_id: pending.id,
                value,
            };
            let sent = runtime
                .store
                .with_current_public_profile(&pending.approval, || self.net.try_send(&message))?;
            if sent {
                pending.phase = Phase::Submitted;
                pending.deadline = now + PHASE_TIMEOUT;
                runtime.next_attempt = now + Duration::from_millis(PROFILE_RENEWAL_MS);
                let _ = runtime.store.observe_profile_publication(
                    &pending.approval,
                    ProfilePublicationResult::Submitted,
                );
            } else {
                pending.phase = Phase::Cancelling;
            }
            return Ok(());
        }
        if !active {
            return Ok(());
        }
        let Some(approval) = approval else {
            runtime.last_approval = None;
            return self.prepare_profile_if_due(now_ms);
        };
        if now < runtime.next_attempt && runtime.last_approval.as_ref() == Some(&approval) {
            return Ok(());
        }
        let id = fresh_id()?;
        let message = IpcMessage::PrepareProfile {
            operation_id: id,
            agent: approval.agent_id,
        };
        if runtime
            .store
            .with_current_public_profile(&approval, || self.net.try_send(&message))?
        {
            runtime.last_approval = Some(approval.clone());
            runtime.pending = Some(Pending {
                id,
                approval,
                phase: Phase::Lookup,
                deadline: now + PHASE_TIMEOUT,
            });
        }
        Ok(())
    }

    fn prepare_profile_if_due(&mut self, now_ms: u64) -> Result<(), AslError> {
        let agent = self.agent_identity.agent_id();
        let store = &mut self.profile_signing.store;
        let Some(approval) = store.profile_signing_due(agent, now_ms)? else {
            return Ok(());
        };
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let sequence = store.reserve_profile_sequence(agent)?;
        if let Some(candidate) =
            admission.prepare_local_profile(&self.agent_identity, &approval, sequence, now_ms)?
        {
            store.observe_profile_candidate(&approval, &candidate)?;
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use asl_types::ids::AgentId;

    #[test]
    fn profile_lookup_and_stale_put_responses_never_credit_a_new_approval() {
        let fixture = crate::transfer::tests::Fixture::new();
        let database = fixture.path().join("profile.sqlite3");
        let mut runtime = ProfileSigningRuntime::open(&database).unwrap();
        let mut cli = open_store(&database).unwrap();
        let agent = AgentId([1; 32]);
        let id = [2; 16];
        let now = Instant::now();
        cli.approve_profile_publication(agent, vec![101]).unwrap();
        runtime.pending = Some(Pending {
            id,
            approval: cli.current_public_profile(agent).unwrap().unwrap(),
            phase: Phase::Lookup,
            deadline: now + PHASE_TIMEOUT,
        });
        assert!(!runtime.handle_response([3; 16], true, now));
        assert!(runtime.handle_response(id, true, now));
        assert!(
            runtime
                .pending
                .as_ref()
                .is_some_and(|p| p.phase == Phase::Ready)
        );
        assert!(
            cli.profile_signing_status()
                .unwrap()
                .last_publication
                .is_none()
        );

        runtime.pending.as_mut().unwrap().phase = Phase::Submitted;
        cli.revoke_profile_signing_approval().unwrap();
        cli.approve_profile_publication(agent, vec![101]).unwrap();
        assert!(runtime.handle_response(id, true, now));
        assert!(
            cli.profile_signing_status()
                .unwrap()
                .last_publication
                .is_none()
        );
    }
}
