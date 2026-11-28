use std::{
    path::Path,
    time::{Duration, Instant},
};

use asl_store::{
    Store, open_store,
    public_profile::{
        PROFILE_RENEWAL_MS, ProfileHandoff, ProfilePublicationResult, ProfileSigningApproval,
    },
};
use asl_types::{
    error::AslError,
    ids::AgentId,
    record::{RecordKind, RecordPayload, decode_record},
};

use super::{NetworkAdmissionStatus, Supervisor, unix_time_ms};
use crate::{
    ipc::IpcMessage,
    profile::{AdmittedNetworkEvent, fresh_id},
};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);
const PHASE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(PartialEq, Eq)]
enum Phase {
    Lookup,
    Ready,
    Submitted,
    Cancelling,
    AwaitCancel([u8; 16]),
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

    pub(super) fn observe_remote_record(
        &mut self,
        local_agent: AgentId,
        event: &AdmittedNetworkEvent,
    ) {
        let AdmittedNetworkEvent::DhtRecordAvailable {
            agent_id,
            kind: RecordKind::Profile,
            registry_sequence,
            record,
            ..
        } = event
        else {
            return;
        };
        if *agent_id == local_agent {
            return;
        }
        let (Ok(signed), Ok(now_ms)) = (decode_record(record), unix_time_ms()) else {
            return;
        };
        let RecordPayload::Profile(profile) = signed.record.payload else {
            return;
        };
        // An unavailable dashboard cache must not interrupt the network admission path.
        let _ = self.store.observe_remote_profile(
            &profile,
            *registry_sequence,
            signed.record.issued_at_ms,
            signed.record.expires_at_ms,
            now_ms,
        );
    }

    pub(super) fn handle_response(&mut self, id: [u8; 16], ok: bool, now: Instant) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
        if let Phase::AwaitCancel(receipt) = pending.phase {
            if receipt != id {
                return pending.id == id;
            }
            if ok && self.store.finish_profile_handoff(pending.id).is_ok() {
                let _ = self.store.observe_profile_publication(
                    &pending.approval,
                    ProfilePublicationResult::NoAcknowledgment,
                );
                self.pending = None;
                self.next_attempt = now + RETRY_INTERVAL;
            } else {
                pending.phase = Phase::Cancelling;
            }
            return true;
        }
        if pending.id != id {
            return false;
        }
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
        let outcome = if ok {
            ProfilePublicationResult::DhtAcknowledged
        } else {
            ProfilePublicationResult::NoAcknowledgment
        };
        if pending.phase == Phase::Submitted {
            if !matches!(
                self.store
                    .acknowledge_profile_handoff(&pending.approval, id, outcome),
                Ok(true)
            ) {
                pending.phase = Phase::Cancelling;
                self.next_poll = now;
                return true;
            }
        } else {
            let _ = self
                .store
                .observe_profile_publication(&pending.approval, outcome);
        }
        if !ok {
            self.next_attempt = now + RETRY_INTERVAL;
        }
        self.pending = None;
        true
    }
}

impl Supervisor {
    pub(super) fn poll_profile_signing(&mut self, now: Instant, now_ms: u64) {
        if now < self.profile_signing.next_poll {
            return;
        }
        self.profile_signing.next_poll = now + POLL_INTERVAL;
        let active = self.net.is_running()
            && self.network_admission_status == NetworkAdmissionStatus::Active;
        let local = self.agent_id();
        let _ = self
            .profile_signing
            .store
            .advance_profile_lookup(active, |operation_id, agent| {
                if agent == local {
                    return Ok(false);
                }
                self.net.try_send(&IpcMessage::LookupProfile {
                    operation_id,
                    agent,
                })
            });
        if self.profile_signing.pending.is_none() {
            match self.profile_signing.store.profile_handoff() {
                Ok(Some(old)) => {
                    if asl_policy::sandbox::confirmed_process_exit(old.net_pid) {
                        let _ = self
                            .profile_signing
                            .store
                            .finish_profile_handoff(old.operation);
                    }
                    return;
                }
                Err(_) => return,
                Ok(None) => {}
            }
        }
        if !self.net.is_running() {
            return;
        }
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
            if matches!(pending.phase, Phase::AwaitCancel(_)) && now < pending.deadline {
                return Ok(());
            }
            if approval.as_ref() != Some(&pending.approval)
                || now >= pending.deadline
                || pending.phase == Phase::Cancelling
            {
                pending.phase = Phase::Cancelling;
                let receipt_id = fresh_id()?;
                if self.net.try_send(&IpcMessage::CancelProfile {
                    operation_id: pending.id,
                    receipt_id,
                })? {
                    pending.phase = Phase::AwaitCancel(receipt_id);
                    pending.deadline = now + PHASE_TIMEOUT;
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
                .prepare_local_profile(
                    &self.agent_identity,
                    &runtime.store,
                    &pending.approval,
                    sequence,
                    now_ms,
                )?
                .ok_or(AslError::InvalidPolicyState)?;
            if !runtime
                .store
                .observe_profile_candidate(&pending.approval, &value)?
            {
                pending.phase = Phase::Cancelling;
                return Ok(());
            }
            let net_pid = self
                .net
                .child
                .as_ref()
                .map(|c| c.id())
                .unwrap_or(std::process::id());
            if !runtime.store.reserve_profile_handoff(
                &pending.approval,
                ProfileHandoff {
                    operation: pending.id,
                    net_pid,
                },
            )? {
                pending.phase = Phase::Cancelling;
                return Ok(());
            }
            let operation_id = pending.id;
            let sent = runtime.store.with_current_profile_handoff(
                &pending.approval,
                operation_id,
                value,
                |value| {
                    self.net.try_send(&IpcMessage::PublishProfile {
                        operation_id,
                        value,
                    })
                },
            )?;
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
        if let Some(candidate) = admission.prepare_local_profile(
            &self.agent_identity,
            store,
            &approval,
            sequence,
            now_ms,
        )? {
            store.observe_profile_candidate(&approval, &candidate)?;
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

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

    #[test]
    fn profile_revoke_waits_for_net_cancellation_receipt_not_a_stale_put_reply() {
        let fixture = crate::transfer::tests::Fixture::new();
        let database = fixture.path().join("profile.sqlite3");
        let mut runtime = ProfileSigningRuntime::open(&database).unwrap();
        let mut cli = open_store(&database).unwrap();
        let agent = AgentId([4; 32]);
        let id = [5; 16];
        let receipt = [6; 16];
        let now = Instant::now();
        cli.approve_profile_publication(agent, vec![101]).unwrap();
        let approval = cli.current_public_profile(agent).unwrap().unwrap();
        assert!(
            runtime
                .store
                .reserve_profile_handoff(
                    &approval,
                    ProfileHandoff {
                        operation: id,
                        net_pid: std::process::id()
                    }
                )
                .unwrap()
        );
        runtime.pending = Some(Pending {
            id,
            approval,
            phase: Phase::Submitted,
            deadline: now + PHASE_TIMEOUT,
        });
        cli.revoke_profile_signing_approval().unwrap();
        assert!(cli.current_public_profile(agent).unwrap().is_none());
        assert!(runtime.handle_response(id, true, now));
        assert_eq!(cli.profile_handoff().unwrap().unwrap().operation, id);
        let pending = runtime.pending.as_mut().unwrap();
        assert!(pending.phase == Phase::Cancelling);
        pending.phase = Phase::AwaitCancel(receipt);
        assert!(runtime.handle_response(id, true, now));
        assert!(!runtime.handle_response([8; 16], true, now));
        assert!(cli.profile_signing_status().unwrap().change_pending);
        assert!(runtime.handle_response(receipt, true, now));
        let status = cli.profile_signing_status().unwrap();
        assert!(!status.change_pending && status.approval.is_none());
        assert!(cli.profile_handoff().unwrap().is_none());
    }
}
