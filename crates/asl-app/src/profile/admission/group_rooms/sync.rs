use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use asl_groups::{
    local_state::{RoomBinding, seal_with_history},
    membership::{RoomOrigin, read_sync_commit, sync_epoch_binding},
};
use asl_net::transport::REQUEST_TIMEOUT;
use asl_store::{
    Store,
    group_state::{
        MLS_SYNC_RETENTION_MS, MlsEpochBindings, MlsJournalEntry, MlsJournalKind, MlsRoomUpdate,
        MlsSyncAddAuthority, MlsSyncReadAuthority, RoomVersion,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{DeviceCertificate, GroupBody, GroupMembership, GroupPacket},
};
use openmls::prelude::{
    CredentialWithKey, OpenMlsProvider, ProcessedMessageContent, Proposal, ProposalOrRefType,
    Sender,
};

use super::{CoreAdmission, LocalRoomCandidate, MlsNetworkOutcome};
use crate::{
    network::NetworkCommand,
    profile::admission::{ProofVerificationBudget, fresh_id},
};

const MAX_SYNC_RUNS: usize = 5;
const STEP_INTERVAL: Duration = Duration::from_millis(500);

pub(super) struct SyncClock {
    sampled_at_ms: u64,
    started: Instant,
    expires_at_ms: u64,
    deadline: Option<Instant>,
}

impl SyncClock {
    pub(super) fn inbound(sampled_at_ms: u64, expires_at_ms: u64) -> Self {
        Self {
            sampled_at_ms,
            started: Instant::now(),
            expires_at_ms,
            deadline: None,
        }
    }

    pub(super) fn now_ms(&self) -> Result<u64, AslError> {
        self.now_at(Instant::now())
    }

    fn now_at(&self, now: Instant) -> Result<u64, AslError> {
        let elapsed = u64::try_from(now.saturating_duration_since(self.started).as_millis())
            .map_err(|_| AslError::ExpiredMessage)?;
        let now_ms = self.sampled_at_ms.saturating_add(elapsed);
        if now_ms >= self.expires_at_ms || self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(AslError::ExpiredMessage);
        }
        Ok(now_ms)
    }
}

pub(in crate::profile::admission) struct MlsSyncRuntime {
    runs: HashMap<Hash32, SyncRun>,
    serve_budget: ProofVerificationBudget,
}

impl Default for MlsSyncRuntime {
    fn default() -> Self {
        Self {
            runs: HashMap::new(),
            serve_budget: ProofVerificationBudget::new(Instant::now()),
        }
    }
}

struct SyncRun {
    connection_id: [u8; 16],
    source: DeviceCertificate,
    expected: RoomVersion,
    phase: SyncPhase,
}

enum SyncPhase {
    Ready(Instant),
    Waiting {
        handle: [u8; 16],
        request: GroupPacket,
        expires_at_ms: u64,
        deadline: Instant,
    },
}

impl MlsSyncRuntime {
    pub(in crate::profile::admission) fn expire(&mut self, now_ms: u64) {
        let now = Instant::now();
        self.runs.retain(|_, run| match &run.phase {
            SyncPhase::Ready(_) => true,
            SyncPhase::Waiting {
                expires_at_ms,
                deadline,
                ..
            } => now < *deadline && now_ms < *expires_at_ms,
        });
    }

    pub(in crate::profile::admission) fn disconnect(&mut self, connection_id: [u8; 16]) {
        self.runs
            .retain(|_, run| run.connection_id != connection_id);
    }

    pub(in crate::profile::admission) fn fail(
        &mut self,
        connection_id: [u8; 16],
        handle: [u8; 16],
    ) {
        self.runs.retain(|_, run| {
            run.connection_id != connection_id
                || !matches!(&run.phase, SyncPhase::Waiting { handle: used, .. } if *used == handle)
        });
    }
}

impl CoreAdmission {
    /// Start only from a trusted Core trigger and the current local snapshot.
    pub(crate) fn start_mls_sync(
        &mut self,
        store: &Store,
        connection_id: [u8; 16],
        wire_id: Hash32,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        self.mls_sync.expire(now_ms);
        if self.mls_sync.runs.len() >= MAX_SYNC_RUNS || self.mls_sync.runs.contains_key(&wire_id) {
            return Err(AslError::QuotaExceeded);
        }
        let (source, candidate) =
            self.load_sync_candidate(store, connection_id, wire_id, directories, now_ms)?;
        if candidate.history.remaining_catchup() == 0 {
            return Err(AslError::QuotaExceeded);
        }
        let phase = send_step(&candidate, wire_id, connection_id, now_ms, enqueue)?;
        self.mls_sync.runs.insert(
            wire_id,
            SyncRun {
                connection_id,
                source,
                expected: candidate.version,
                phase,
            },
        );
        Ok(())
    }

    /// At most one continuation per Core tick. An unavailable route or a
    /// changed local snapshot stops the run instead of selecting another peer.
    pub(crate) fn poll_mls_sync(
        &mut self,
        store: &Store,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        self.mls_sync.expire(now_ms);
        let now = Instant::now();
        let Some((&wire_id, _)) = self
            .mls_sync
            .runs
            .iter()
            .find(|(_, run)| matches!(run.phase, SyncPhase::Ready(at) if now >= at))
        else {
            return Ok(());
        };
        let mut run = self
            .mls_sync
            .runs
            .remove(&wire_id)
            .ok_or(AslError::InvalidPolicyState)?;
        let (source, candidate) =
            self.load_sync_candidate(store, run.connection_id, wire_id, directories, now_ms)?;
        if source != run.source || candidate.version != run.expected {
            return Err(AslError::PolicyVersionConflict);
        }
        run.phase = send_step(&candidate, wire_id, run.connection_id, now_ms, enqueue)?;
        self.mls_sync.runs.insert(wire_id, run);
        Ok(())
    }

    pub(super) fn serve_mls_sync_step(
        &mut self,
        store: &Store,
        connection_id: [u8; 16],
        request: &GroupPacket,
        directories: &HashMap<AgentId, Vec<u8>>,
        clock: &SyncClock,
    ) -> Result<GroupPacket, AslError> {
        let now_ms = clock.now_ms()?;
        request.validate_request()?;
        let GroupBody::Membership(GroupMembership::SyncRequest { epoch_binding }) = request.body
        else {
            return Err(AslError::InvalidMessage);
        };
        let (_, peer) = self.admitted_peer_identity(connection_id, now_ms)?;
        if !store.has_mls_sync_member(request.group_id, &peer)? {
            return Err(AslError::PolicyDenied);
        }
        if !self.mls_sync.serve_budget.try_acquire(Instant::now()) {
            return Err(AslError::QuotaExceeded);
        }
        let (requester, candidate) =
            self.load_sync_candidate(store, connection_id, request.group_id, directories, now_ms)?;
        let head = candidate.version.mls_epoch;
        let head_binding = sync_epoch_binding(&candidate.group, candidate.provider.crypto())?;
        let chain_id = self.resolver.deployment().chain_id;
        let mut suffix_expiry = u64::MAX;
        let step = store.read_authorized_mls_sync_step(
            candidate.sync_authority(request.group_id, &requester.peer_id, chain_id),
            (request.epoch < head).then_some((request.epoch, head_binding)),
            || clock.now_ms(),
            |step| {
                suffix_expiry = suffix_expiry.min(step.expires_at_ms);
                Ok(step.version == candidate.version
                    && step.local_id == candidate.local_id
                    && (step.base_epoch != request.epoch || step.bindings.base == epoch_binding)
                    && candidate.history.digest(step.base_epoch)
                        == Some(step.bindings.digest(
                            &step.local_id,
                            request.group_id,
                            &self.local_hello.peer_id,
                            (step.base_epoch, step.expires_at_ms),
                            &step.signer,
                            &step.commit,
                        )))
            },
        )?;
        let step_expiry = step.as_ref().map(|_| suffix_expiry);
        let membership = if head == request.epoch && head_binding == epoch_binding {
            GroupMembership::AtHead {
                epoch_binding: head_binding,
            }
        } else if let Some(step) = step {
            GroupMembership::SyncCommit(step.commit)
        } else {
            GroupMembership::SyncUnavailable
        };
        let response = GroupPacket {
            body: GroupBody::Membership(membership),
            ..request.clone()
        };
        request.match_reply(&response)?;
        if matches!(
            response.body,
            GroupBody::Membership(GroupMembership::SyncCommit(_))
        ) {
            read_sync_commit(request, &response)?;
        }
        let now_ms = self.sync_peer_is_live(connection_id, &requester.peer_id, clock)?;
        if step_expiry.is_some_and(|expiry| now_ms >= expiry)
            || candidate
                .roster
                .members
                .iter()
                .any(|member| now_ms >= member.certificate.expires_at_ms)
        {
            return Err(AslError::ExpiredMessage);
        }
        Ok(response)
    }

    pub(super) fn receive_mls_sync_reply(
        &mut self,
        store: &mut Store,
        connection_id: [u8; 16],
        request_handle: [u8; 16],
        response: &GroupPacket,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<Option<MlsNetworkOutcome>, AslError> {
        let started = Instant::now();
        self.mls_sync.expire(now_ms);
        let wire_id = response.group_id;
        let Some(run) = self.mls_sync.runs.get(&wire_id) else {
            return Ok(None);
        };
        let SyncPhase::Waiting {
            handle, request, ..
        } = &run.phase
        else {
            return Ok(None);
        };
        if run.connection_id != connection_id || *handle != request_handle {
            return Ok(None);
        }
        request.match_reply(response)?;
        let mut run = self
            .mls_sync
            .runs
            .remove(&wire_id)
            .ok_or(AslError::InvalidPolicyState)?;
        let SyncPhase::Waiting {
            ref request,
            expires_at_ms,
            deadline,
            ..
        } = run.phase
        else {
            return Err(AslError::InvalidPolicyState);
        };
        let clock = SyncClock {
            sampled_at_ms: now_ms,
            started,
            expires_at_ms,
            deadline: Some(deadline),
        };
        let (source, candidate) =
            self.load_sync_candidate(store, connection_id, wire_id, directories, now_ms)?;
        let base = sync_epoch_binding(&candidate.group, candidate.provider.crypto())?;
        if source != run.source
            || candidate.version != run.expected
            || candidate.version.mls_epoch != request.epoch
            || request.body
                != GroupBody::Membership(GroupMembership::SyncRequest {
                    epoch_binding: base,
                })
        {
            return Err(AslError::PolicyVersionConflict);
        }
        match &response.body {
            GroupBody::Membership(GroupMembership::AtHead { .. }) => {
                let chain_id = self.resolver.deployment().chain_id;
                store.read_authorized_mls_sync_step(
                    candidate.sync_authority(wire_id, &source.peer_id, chain_id),
                    None,
                    || clock.now_ms(),
                    |_| Ok(false),
                )?;
                self.sync_peer_is_live(connection_id, &source.peer_id, &clock)?;
                Ok(Some(MlsNetworkOutcome::SyncHead {
                    wire_id,
                    version: run.expected,
                }))
            }
            GroupBody::Membership(GroupMembership::SyncUnavailable) => {
                Ok(Some(MlsNetworkOutcome::SyncStopped { wire_id }))
            }
            GroupBody::Membership(GroupMembership::SyncCommit(ciphertext)) => {
                if candidate.history.remaining_catchup() == 0 {
                    return Ok(Some(MlsNetworkOutcome::SyncStopped { wire_id }));
                }
                let step = ReceivedStep {
                    connection_id,
                    source: &source.peer_id,
                    request,
                    response,
                    ciphertext,
                    base,
                };
                let version = self.apply_sync_add(store, candidate, step, directories, &clock)?;
                run.expected = version;
                run.phase = SyncPhase::Ready(Instant::now() + STEP_INTERVAL);
                self.mls_sync.runs.insert(wire_id, run);
                Ok(Some(MlsNetworkOutcome::SyncAdvanced { wire_id, version }))
            }
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn load_sync_candidate(
        &mut self,
        store: &Store,
        connection_id: [u8; 16],
        wire_id: Hash32,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<(DeviceCertificate, LocalRoomCandidate), AslError> {
        let source = self
            .mls_target(connection_id, directories, now_ms)?
            .certificate;
        let candidate = self
            .room_evidence(directories, now_ms)
            .load_candidate(store, wire_id)?
            .ok_or(AslError::PolicyDenied)?;
        if !candidate
            .roster
            .members
            .iter()
            .any(|member| member.certificate == source)
        {
            return Err(AslError::PolicyDenied);
        }
        store.read_authorized_mls_sync_step(
            candidate.sync_authority(
                wire_id,
                &source.peer_id,
                self.resolver.deployment().chain_id,
            ),
            None,
            || Ok(now_ms),
            |_| Ok(false),
        )?;
        Ok((source, candidate))
    }

    fn apply_sync_add(
        &mut self,
        store: &mut Store,
        mut candidate: LocalRoomCandidate,
        step: ReceivedStep<'_>,
        directories: &HashMap<AgentId, Vec<u8>>,
        clock: &SyncClock,
    ) -> Result<RoomVersion, AslError> {
        let now_ms = clock.now_ms()?;
        let wire_id = step.request.group_id;
        let message = read_sync_commit(step.request, step.response)?;
        let processed = candidate
            .group
            .process_message(&candidate.provider, message)
            .map_err(|_| AslError::InvalidMessage)?;
        // The authenticated transport device may forward the commit, but
        // only the creator in the base MLS tree can sign this Add.
        if processed.sender() != &Sender::Member(candidate.roster.creator_index) {
            return Err(AslError::PolicyDenied);
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(AslError::InvalidMessage);
        };
        let (added, added_leaf) = {
            let mut proposals = staged.queued_proposals();
            let proposal = proposals.next().ok_or(AslError::PolicyDenied)?;
            let Proposal::Add(add) = proposal.proposal() else {
                return Err(AslError::PolicyDenied);
            };
            if proposals.next().is_some()
                || proposal.proposal_or_ref_type() != ProposalOrRefType::Proposal
            {
                return Err(AslError::PolicyDenied);
            }
            let leaf = add.key_package().leaf_node().clone();
            let cert = crate::profile::group_credential::leaf_certificate(&CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: leaf.signature_key().clone(),
            })?;
            (cert, leaf)
        };
        candidate
            .group
            .merge_staged_commit(&candidate.provider, *staged)
            .map_err(|_| AslError::InvalidMessage)?;
        let epoch = candidate.group.epoch().as_u64();
        if step.request.epoch.checked_add(1) != Some(epoch) {
            return Err(AslError::PolicyVersionConflict);
        }
        let origin = RoomOrigin::from_context(
            wire_id,
            candidate.group.extensions(),
            candidate.provider.crypto(),
        )?;
        let roster = self.room_evidence(directories, now_ms).verify_roster(
            &origin,
            candidate.group.own_leaf_index(),
            candidate.group.members(),
        )?;
        let added_peer = &added.peer_id;
        if roster.creator != candidate.roster.creator
            || candidate.roster.members.iter().any(|before| {
                &before.certificate.peer_id == added_peer
                    || !roster
                        .members
                        .iter()
                        .any(|after| before.certificate == after.certificate)
            })
            || roster.members.len() != candidate.roster.members.len() + 1
            || !candidate.group.members().any(|member| {
                member.credential == *added_leaf.credential()
                    && member.signature_key.as_slice() == added_leaf.signature_key().as_slice()
            })
            || !roster
                .members
                .iter()
                .any(|after| after.certificate == added)
        {
            return Err(AslError::PolicyDenied);
        }
        let binding = RoomBinding {
            local_id: &candidate.local_id,
            wire_id,
            device: &self.local_hello.peer_id,
        };
        let bindings = MlsEpochBindings {
            base: step.base,
            next: sync_epoch_binding(&candidate.group, candidate.provider.crypto())?,
        };
        let recorded_at_ms = clock.now_ms()?;
        let expiry = recorded_at_ms
            .checked_add(MLS_SYNC_RETENTION_MS)
            .ok_or(AslError::ExpiredMessage)?;
        let signer = &candidate.roster.creator;
        candidate.history.append_downloaded(
            step.request.epoch,
            bindings.digest(
                binding.local_id,
                wire_id,
                binding.device,
                (step.request.epoch, expiry),
                signer,
                step.ciphertext,
            ),
        )?;
        let revision = candidate
            .version
            .revision
            .checked_add(1)
            .ok_or(AslError::QuotaExceeded)?;
        let snapshot = seal_with_history(
            &binding,
            revision,
            &candidate.group,
            &candidate.provider,
            &candidate.history,
        )?;
        let members = roster
            .members
            .iter()
            .map(|member| member.certificate.peer_id.clone())
            .collect::<Vec<_>>();
        store.commit_verified_mls_sync_add(
            MlsRoomUpdate {
                local_id: &candidate.local_id,
                wire_id,
                expected: candidate.version,
                mls_epoch: epoch,
                sealed_snapshot: &snapshot,
                members: &members,
                event: Some(MlsJournalEntry {
                    sender: signer,
                    kind: MlsJournalKind::SyncCommit(bindings),
                    ciphertext: step.ciphertext,
                }),
            },
            MlsSyncAddAuthority {
                source: step.source,
                added: added_peer,
                members: &roster.members,
                chain_id: self.resolver.deployment().chain_id,
            },
            recorded_at_ms,
            || self.sync_peer_is_live(step.connection_id, step.source, clock),
        )
    }

    fn sync_peer_is_live(
        &mut self,
        connection_id: [u8; 16],
        expected_peer: &PeerId,
        clock: &SyncClock,
    ) -> Result<u64, AslError> {
        let now_ms = clock.now_ms()?;
        let (_, actual) = self.admitted_peer_identity(connection_id, now_ms)?;
        if &actual != expected_peer {
            return Err(AslError::InvalidIdentity);
        }
        Ok(now_ms)
    }
}

impl LocalRoomCandidate {
    fn sync_authority<'a>(
        &'a self,
        wire_id: Hash32,
        requester: &'a PeerId,
        chain_id: u64,
    ) -> MlsSyncReadAuthority<'a> {
        MlsSyncReadAuthority {
            wire_id,
            expected: self.version,
            creator: &self.roster.creator,
            requester,
            members: &self.roster.members,
            chain_id,
        }
    }
}

struct ReceivedStep<'a> {
    connection_id: [u8; 16],
    source: &'a PeerId,
    request: &'a GroupPacket,
    response: &'a GroupPacket,
    ciphertext: &'a [u8],
    base: Hash32,
}

fn send_step(
    candidate: &LocalRoomCandidate,
    wire_id: Hash32,
    connection_id: [u8; 16],
    now_ms: u64,
    enqueue: impl FnOnce(NetworkCommand) -> Result<(), AslError>,
) -> Result<SyncPhase, AslError> {
    let request = GroupPacket {
        group_id: wire_id,
        message_id: Id128(fresh_id()?),
        epoch: candidate.version.mls_epoch,
        body: GroupBody::Membership(GroupMembership::SyncRequest {
            epoch_binding: sync_epoch_binding(&candidate.group, candidate.provider.crypto())?,
        }),
    };
    request.validate_request()?;
    let handle = fresh_id()?;
    let expires_at_ms = now_ms.saturating_add(REQUEST_TIMEOUT.as_millis() as u64);
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    enqueue(NetworkCommand::SendGroup {
        connection_id,
        request_handle: handle,
        deadline_ms: expires_at_ms,
        request: request.clone(),
    })?;
    Ok(SyncPhase::Waiting {
        handle,
        request,
        expires_at_ms,
        deadline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_deadline_counts_time_spent_after_dispatch() {
        let started = Instant::now();
        let clock = SyncClock {
            sampled_at_ms: 1_000,
            started,
            expires_at_ms: 1_005,
            deadline: Some(started + Duration::from_millis(4)),
        };
        assert_eq!(
            clock.now_at(started + Duration::from_millis(3)).unwrap(),
            1_003
        );
        assert!(matches!(
            clock.now_at(started + Duration::from_millis(4)),
            Err(AslError::ExpiredMessage)
        ));
        let clock = SyncClock {
            deadline: None,
            ..clock
        };
        assert!(matches!(
            clock.now_at(started + Duration::from_millis(5)),
            Err(AslError::ExpiredMessage)
        ));
    }
}
