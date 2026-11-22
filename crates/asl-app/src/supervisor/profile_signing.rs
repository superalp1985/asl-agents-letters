use std::{
    path::Path,
    time::{Duration, Instant},
};

use asl_store::{Store, open_store};
use asl_types::error::AslError;

use super::{NetworkAdmissionStatus, Supervisor};

pub(super) struct ProfileSigningRuntime {
    store: Store,
    next_poll: Instant,
}

impl ProfileSigningRuntime {
    pub(super) fn open(database: &Path) -> Result<Self, AslError> {
        Ok(Self {
            store: open_store(database)?,
            next_poll: Instant::now(),
        })
    }
}

impl Supervisor {
    pub(super) fn poll_profile_signing(&mut self, now: Instant, now_ms: u64) {
        if now < self.profile_signing.next_poll
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || !self.net.is_running()
        {
            return;
        }
        self.profile_signing.next_poll = now + Duration::from_secs(2);
        if self.prepare_profile_if_due(now_ms).is_err() {
            self.profile_signing.next_poll = now + Duration::from_secs(30);
        }
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
