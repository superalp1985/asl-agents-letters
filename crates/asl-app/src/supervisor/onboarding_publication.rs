use std::time::{Duration, Instant};

use asl_types::error::AslError;

use super::Supervisor;
use crate::{
    identity_onboarding::{self, OnboardingPhaseV1},
    network::NetworkCommand,
    network_identity::NetworkAdmissionStatus,
    paths::AppPaths,
    profile::fresh_id,
};

const RETRY_INTERVAL: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
enum Phase {
    Prepare([u8; 16]),
    Publish([u8; 16]),
}

struct Pending {
    phase: Phase,
    deadline: Instant,
    commitment: String,
    sequence: u64,
    commitment_bytes: [u8; 32],
}

pub(super) struct OnboardingPublicationRuntime {
    pending: Option<Pending>,
    next_attempt: Instant,
}

impl OnboardingPublicationRuntime {
    pub(super) fn new() -> Self {
        Self {
            pending: None,
            next_attempt: Instant::now(),
        }
    }
}

impl Supervisor {
    pub(super) fn poll_onboarding_directory_publication(&mut self, now: Instant) {
        if self.network_admission_status != NetworkAdmissionStatus::Active || !self.net.is_running()
        {
            return;
        }
        if let Some(pending) = self.onboarding_publication.pending.as_ref() {
            if now < pending.deadline {
                return;
            }
            self.onboarding_publication.pending = None;
            self.onboarding_publication.next_attempt = now + RETRY_INTERVAL;
        }
        if now < self.onboarding_publication.next_attempt {
            return;
        }
        self.onboarding_publication.next_attempt = now + RETRY_INTERVAL;
        let Ok(paths) = AppPaths::open_existing(&self.home) else {
            return;
        };
        let Ok(Some(status)) = identity_onboarding::status(&paths) else {
            return;
        };
        if status.phase != OnboardingPhaseV1::DirectoryInstalled {
            return;
        }
        let Ok(operation_id) = fresh_id() else {
            return;
        };
        let Some(commitment_bytes) = parse_commitment(&status.state_commitment) else {
            return;
        };
        if self
            .send_network_command(NetworkCommand::PrepareDirectory {
                operation_id,
                agent: self.agent_identity.agent_id(),
            })
            .is_ok()
        {
            self.onboarding_publication.pending = Some(Pending {
                phase: Phase::Prepare(operation_id),
                deadline: now + ATTEMPT_TIMEOUT,
                commitment: status.state_commitment,
                sequence: status.registry_sequence,
                commitment_bytes,
            });
        }
    }

    pub(super) fn advance_onboarding_publication(
        &mut self,
        operation_id: [u8; 16],
        now: Instant,
    ) -> Result<bool, AslError> {
        let Some(pending) = self.onboarding_publication.pending.as_ref() else {
            return Ok(false);
        };
        let phase = pending.phase;
        let id = match phase {
            Phase::Prepare(id) | Phase::Publish(id) => id,
        };
        if id != operation_id {
            return Ok(false);
        }
        let sequence = pending.sequence;
        let commitment_bytes = pending.commitment_bytes;
        match phase {
            Phase::Prepare(_) => {
                let paths = AppPaths::open_existing(&self.home)?;
                let bytes = std::fs::read(paths.signed_device_directory())?;
                identity_onboarding::verify_signed_directory(
                    &bytes,
                    self.agent_identity.agent_id(),
                    sequence,
                    commitment_bytes,
                )?;
                self.send_network_command(NetworkCommand::PublishDirectory {
                    operation_id,
                    value: bytes,
                })?;
                if let Some(pending) = self.onboarding_publication.pending.as_mut() {
                    pending.phase = Phase::Publish(operation_id);
                    pending.deadline = now + ATTEMPT_TIMEOUT;
                }
            }
            Phase::Publish(_) => {
                let paths = AppPaths::open_existing(&self.home)?;
                let commitment = self
                    .onboarding_publication
                    .pending
                    .as_ref()
                    .map(|pending| pending.commitment.clone())
                    .ok_or(AslError::InvalidPolicyState)?;
                self.onboarding_publication.pending = None;
                let _ = identity_onboarding::mark_directory_published(&paths, &commitment);
            }
        }
        Ok(true)
    }

    pub(super) fn note_onboarding_publication_failure(
        &mut self,
        operation_id: [u8; 16],
    ) -> Result<bool, AslError> {
        let Some(pending) = self.onboarding_publication.pending.as_ref() else {
            return Ok(false);
        };
        let id = match pending.phase {
            Phase::Prepare(id) | Phase::Publish(id) => id,
        };
        if id != operation_id {
            return Ok(false);
        }
        let paths = AppPaths::open_existing(&self.home)?;
        let commitment = pending.commitment.clone();
        self.onboarding_publication.pending = None;
        self.onboarding_publication.next_attempt = Instant::now() + RETRY_INTERVAL;
        let _ = identity_onboarding::note_publication_failure(
            &paths,
            &commitment,
            "DHT directory publication failed; Core will retry",
        );
        Ok(true)
    }
}

fn parse_commitment(value: &str) -> Option<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let mut bytes = [0; 32];
    alloy_primitives::hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}
