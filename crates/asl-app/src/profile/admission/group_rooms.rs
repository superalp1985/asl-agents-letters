//! Core boundary for attested MLS rooms. None of these operations activates
//! a room, enables a transport or grants access to files.

mod application;
mod delivery;
mod directories;
mod incoming;
mod network;
mod outgoing;
mod removal;
mod sync;

pub use application::MlsApplicationReceive;
pub use delivery::{MlsApplicationDispatch, MlsApplicationSendToConnection};
pub(super) use directories::GroupDirectoryCache;
pub(super) use network::MlsJoinAttempts;
pub use network::{MlsInviteSend, MlsJoinSend, MlsNetworkOutcome};
pub(super) use sync::MlsSyncRuntime;

use std::collections::{HashMap, HashSet, hash_map::Entry};

use asl_groups::{
    local_state::{RoomBinding, RoomProvider, SyncHistory, restore_with_history, seal},
    membership::{GROUP_CIPHERSUITE, RoomOrigin, stage_welcome},
    pending_join,
};
use asl_store::{
    Store,
    group_state::{
        MlsIncomingInvite, MlsJoinedRoom, MlsMemberEvidence, PendingMlsRoom, RoomVersion,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, PeerId},
    protocol::{DeviceCertificate, GroupPacket, MAX_GROUP_MEMBERS},
    record::RecordPayload,
    task::GroupId,
};
use openmls::prelude::{
    CredentialWithKey, GroupId as MlsGroupId, LeafNodeIndex, Member, MlsGroup, OpenMlsProvider,
};
use openmls_basic_credential::SignatureKeyPair;

use crate::{
    chain::IdentityResolver,
    identity::AgentIdentity,
    profile::{
        RecordHistory, VerifiedRecord,
        group_credential::{issue_group_credential, leaf_certificate, verify_directory_leaf},
        resolve_active, verify_record,
    },
};

use super::{CoreAdmission, PeerAdmission, transport_ed25519_key};

/// Only a local consistency result. The room remains `needs_sync` and
/// future operations must recheck the versions and authorization evidence.
pub struct ReconciledMlsRoom {
    pub local_id: GroupId,
    pub version: RoomVersion,
    pub creator: PeerId,
    pub members: Vec<PeerId>,
}

struct ApprovedMlsWelcome<'a> {
    connection_id: [u8; 16],
    invite: &'a MlsIncomingInvite,
    reply: &'a GroupPacket,
    local_id: &'a GroupId,
    local_name: &'a str,
    rejoin_base: Option<RoomVersion>,
    /// Core supplies locally collected signed device directories, not an
    /// unverified directory bundle from the Welcome or from a model.
    directories: &'a HashMap<AgentId, Vec<u8>>,
}

impl CoreAdmission {
    pub(crate) fn enable_loopback_mls_directories(&mut self) {
        self.group_directories.get_or_insert_with(Default::default);
    }

    pub(super) fn observe_admitted_mls_directory(&mut self, record: &VerifiedRecord) {
        let Some(directories) = &mut self.group_directories else {
            return;
        };
        let agent = record.signed().record.payload.agent_id();
        if !self.dht_histories.contains_key(&agent)
            && self.dht_histories.len() >= super::MAX_DHT_RECORD_OWNERS
        {
            return;
        }
        let history = self.dht_histories.entry(agent).or_insert_with(|| {
            RecordHistory::new(agent, super::MAX_DEVICE_OBSERVATIONS)
                .expect("fixed record history limit is valid")
        });
        // The owner watermark survives eviction of the cached directory bytes.
        if history.observe(record).is_ok() {
            directories.observe(record);
        }
    }

    /// Create a closed room and register its verified local device in the
    /// same transaction.
    pub fn create_local_mls_room(
        &mut self,
        store: &mut Store,
        root: &AgentIdentity,
        local_id: &GroupId,
        local_name: &str,
        now_ms: u64,
    ) -> Result<(Hash32, RoomVersion), AslError> {
        self.create_local_mls_room_linked(store, root, local_id, local_name, now_ms, None)
    }

    pub(crate) fn create_local_mls_room_linked(
        &mut self,
        store: &mut Store,
        root: &AgentIdentity,
        local_id: &GroupId,
        local_name: &str,
        now_ms: u64,
        shard_root: Option<Hash32>,
    ) -> Result<(Hash32, RoomVersion), AslError> {
        let expected_policy = store.policy_revision()?;
        let local = self.local_hello.device_certificate.clone();
        let provider = RoomProvider::default();
        let origin = RoomOrigin::generate(&local, &provider)?;
        let wire_id = origin.wire_id();
        let (signer, credential) = issue_group_credential(root, wire_id, &local, now_ms)?;
        let config = origin.group_config()?;
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            MlsGroupId::from_slice(wire_id.as_bytes()),
            credential,
        )
        .map_err(|_| AslError::InvalidPolicyState)?;
        signer
            .store(provider.storage())
            .map_err(|_| AslError::InvalidPolicyState)?;
        let roster = self.room_evidence(&HashMap::new(), now_ms).verify_roster(
            &origin,
            group.own_leaf_index(),
            group.members(),
        )?;
        let [creator] = roster.members.as_slice() else {
            return Err(AslError::InvalidPolicyState);
        };
        let binding = RoomBinding {
            local_id,
            wire_id,
            device: &local.peer_id,
        };
        let sealed = seal(&binding, 1, &group, &provider)?;
        let version = store.create_mls_room_linked(
            PendingMlsRoom {
                local_id,
                wire_id,
                creator: &local.peer_id,
                local_name,
                mls_epoch: 0,
                sealed_snapshot: &sealed,
            },
            creator,
            self.resolver.deployment().chain_id,
            expected_policy,
            now_ms,
            shard_root,
        )?;
        Ok((wire_id, version))
    }

    /// Reconcile a paused room after reopening the database. Missing fresh
    /// directories or inconsistent state leave it paused. A match does not
    /// establish that the local epoch is the remote head.
    pub fn reconcile_mls_room(
        &mut self,
        store: &Store,
        wire_id: Hash32,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<Option<ReconciledMlsRoom>, AslError> {
        let chain_id = self.resolver.deployment().chain_id;
        self.room_evidence(directories, now_ms)
            .reconcile(store, wire_id, chain_id)
    }

    /// Consume a durable local approval only when the creator, local leaf,
    /// roster and the currently admitted sender all agree.
    fn finish_approved_mls_welcome(
        &mut self,
        store: &mut Store,
        welcome: ApprovedMlsWelcome<'_>,
        clock: &sync::SyncClock,
    ) -> Result<RoomVersion, AslError> {
        let now_ms = clock.now_ms()?;
        let invite = welcome.invite;
        let expected_policy_revision = store.policy_revision()?;
        let (agent, peer) = self.admitted_peer_identity(welcome.connection_id, now_ms)?;
        if agent != invite.inviter
            || peer != invite.inviter_device
            || self.local_hello.agent_id != invite.recipient
            || self.local_hello.peer_id != invite.recipient_device
        {
            return Err(AslError::InvalidIdentity);
        }
        let (key, sealed) = store
            .pending_mls_join_package(invite, now_ms)?
            .ok_or(AslError::PolicyDenied)?;
        let (request, provider) = pending_join::restore(invite, key, &sealed)?;
        let staged = stage_welcome(&request, welcome.reply, key.package_ref, &provider)?;
        let wire_id = invite.wire_id;
        let origin = RoomOrigin::from_context(
            wire_id,
            staged.group_context().extensions(),
            provider.crypto(),
        )?;
        let roster = self
            .room_evidence(welcome.directories, now_ms)
            .verify_roster(&origin, staged.own_leaf_index(), staged.members())?;
        require_local_group_capacity(store, roster.members.len(), now_ms)?;
        roster.require_welcome_creator(staged.welcome_sender_index(), invite)?;
        let sender = staged
            .members()
            .find(|member| member.index == roster.creator_index)
            .ok_or(AslError::InvalidIdentity)?;
        self.verify_admitted_group_leaf(
            welcome.connection_id,
            wire_id,
            &CredentialWithKey::from(&sender),
            now_ms,
        )?;
        let group = staged
            .into_group(&provider)
            .map_err(|_| AslError::InvalidMessage)?;
        let binding = RoomBinding {
            local_id: welcome.local_id,
            wire_id,
            device: &invite.recipient_device,
        };
        let revision = match welcome.rejoin_base {
            Some(base) => base
                .revision
                .checked_add(1)
                .ok_or(AslError::QuotaExceeded)?,
            None => 1,
        };
        let sealed = seal(&binding, revision, &group, &provider)?;
        let join = MlsJoinedRoom {
            invite,
            key,
            room: PendingMlsRoom {
                local_id: welcome.local_id,
                wire_id,
                creator: &roster.creator,
                local_name: welcome.local_name,
                mls_epoch: group.epoch().as_u64(),
                sealed_snapshot: &sealed,
            },
            members: &roster.members,
            chain_id: self.resolver.deployment().chain_id,
            expected_policy_revision,
        };
        let current_time = || {
            let now = clock.now_ms()?;
            let (agent, device) = self.admitted_peer_identity(welcome.connection_id, now)?;
            if agent != invite.inviter || device != invite.inviter_device {
                return Err(AslError::InvalidIdentity);
            }
            roster.require_current_directories(&mut self.resolver, now)?;
            clock.now_ms()
        };
        match welcome.rejoin_base {
            Some(base) => store.finish_mls_rejoin(join, base, current_time),
            None => store.finish_mls_join(join, current_time),
        }
    }

    fn room_evidence<'a>(
        &'a mut self,
        directories: &'a HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> RoomEvidence<'a> {
        RoomEvidence {
            local: &self.local_hello.device_certificate,
            local_directory: &self.local_signed_directory,
            directories,
            observed_directories: self.group_directories.as_ref(),
            histories: &self.dht_histories,
            peers: &self.peers,
            resolver: &mut self.resolver,
            now_ms,
        }
    }
}

pub(crate) fn require_local_group_capacity(
    store: &Store,
    members: usize,
    now_ms: u64,
) -> Result<(), AslError> {
    use crate::capacity::{CapacityAdmission, admit_group_size, latest_local_capacity};

    if members > MAX_GROUP_MEMBERS {
        return Err(AslError::QuotaExceeded);
    }
    if members > 64
        && !matches!(
            admit_group_size(latest_local_capacity(store)?.as_ref(), members, now_ms),
            CapacityAdmission::Admitted(_),
        )
    {
        return Err(AslError::QuotaExceeded);
    }
    Ok(())
}

struct VerifiedRoster {
    creator: PeerId,
    creator_index: LeafNodeIndex,
    members: Vec<MlsMemberEvidence>,
    directories: HashMap<AgentId, VerifiedRecord>,
}

impl VerifiedRoster {
    fn require_welcome_creator(
        &self,
        welcome_sender: LeafNodeIndex,
        invite: &MlsIncomingInvite,
    ) -> Result<(), AslError> {
        if self.creator_index != welcome_sender || self.creator != invite.inviter_device {
            return Err(AslError::PolicyDenied);
        }
        Ok(())
    }

    fn require_current_directories(
        &self,
        resolver: &mut dyn IdentityResolver,
        now_ms: u64,
    ) -> Result<u64, AslError> {
        let mut expires_at = u64::MAX;
        for (&agent, directory) in &self.directories {
            let record = &directory.signed().record;
            let RecordPayload::DeviceDirectory(devices) = &record.payload else {
                return Err(AslError::InvalidIdentity);
            };
            expires_at = devices
                .devices
                .iter()
                .fold(expires_at.min(record.expires_at_ms), |deadline, cert| {
                    deadline.min(cert.expires_at_ms)
                });
            if now_ms >= expires_at {
                return Err(AslError::ExpiredMessage);
            }
            if resolve_active(agent, now_ms, resolver)? != directory.registry_state {
                return Err(AslError::InvalidIdentity);
            }
        }
        Ok(expires_at)
    }
}

struct RoomEvidence<'a> {
    local: &'a DeviceCertificate,
    local_directory: &'a [u8],
    directories: &'a HashMap<AgentId, Vec<u8>>,
    observed_directories: Option<&'a GroupDirectoryCache>,
    histories: &'a HashMap<AgentId, RecordHistory>,
    peers: &'a HashMap<[u8; 16], PeerAdmission>,
    resolver: &'a mut dyn IdentityResolver,
    now_ms: u64,
}

struct LocalRoomCandidate {
    base: SealedRoom,
    roster: VerifiedRoster,
}

struct SealedRoom {
    local_id: GroupId,
    version: RoomVersion,
    provider: RoomProvider,
    group: MlsGroup,
    signer: SignatureKeyPair,
    creator: PeerId,
    creator_index: LeafNodeIndex,
    leaves: Vec<StoredLeaf>,
    history: SyncHistory,
}

struct StoredLeaf {
    member: Member,
    certificate: DeviceCertificate,
}

impl std::ops::Deref for LocalRoomCandidate {
    type Target = SealedRoom;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl RoomEvidence<'_> {
    fn verify_directory(&mut self, agent: AgentId) -> Result<VerifiedRecord, AslError> {
        let bytes = if agent == self.local.agent_id {
            self.local_directory
        } else {
            self.directories
                .get(&agent)
                .map(Vec::as_slice)
                .or_else(|| self.observed_directories.and_then(|cache| cache.get(agent)))
                .ok_or(AslError::InvalidIdentity)?
        };
        let record = verify_record(bytes, agent, self.now_ms, self.resolver)?;
        check_directory_histories(self.histories, self.peers, agent, &record)?;
        Ok(record)
    }

    fn verify_target(
        &mut self,
        certificate: DeviceCertificate,
    ) -> Result<MlsMemberEvidence, AslError> {
        let record = self.verify_directory(certificate.agent_id)?;
        let RecordPayload::DeviceDirectory(directory) = &record.signed().record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if !directory.devices.contains(&certificate) {
            return Err(AslError::InvalidDeviceCertificate);
        }
        member_evidence(certificate, &record)
    }

    fn verify_roster(
        &mut self,
        origin: &RoomOrigin,
        own_index: LeafNodeIndex,
        members: impl Iterator<Item = Member>,
    ) -> Result<VerifiedRoster, AslError> {
        let mut verified: HashMap<AgentId, VerifiedRecord> = HashMap::new();
        let mut roster = Vec::new();
        let mut peers = HashSet::new();
        let mut creator = None;
        let mut found_local = false;
        for member in members {
            if roster.len() == MAX_GROUP_MEMBERS {
                return Err(AslError::QuotaExceeded);
            }
            let leaf = CredentialWithKey::from(&member);
            let cert = leaf_certificate(&leaf)?;
            if !peers.insert(cert.peer_id.clone())
                || (member.index == own_index && &cert != self.local)
            {
                return Err(AslError::InvalidIdentity);
            }
            let directory = match verified.entry(cert.agent_id) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(self.verify_directory(cert.agent_id)?),
            };
            verify_directory_leaf(origin.wire_id(), &leaf, &cert, directory)?;
            if origin.matches_creator(&cert) {
                creator = Some((cert.peer_id.clone(), member.index));
            }
            if member.index == own_index {
                found_local = true;
            }
            roster.push(member_evidence(cert, directory)?);
        }
        let (creator, creator_index) = creator.ok_or(AslError::PolicyDenied)?;
        if !found_local {
            return Err(AslError::InvalidIdentity);
        }
        Ok(VerifiedRoster {
            creator,
            creator_index,
            members: roster,
            directories: verified,
        })
    }

    fn reconcile(
        &mut self,
        store: &Store,
        wire_id: Hash32,
        chain_id: u64,
    ) -> Result<Option<ReconciledMlsRoom>, AslError> {
        let Some(candidate) = self.load_candidate(store, wire_id)? else {
            return Ok(None);
        };
        let mut members = Vec::with_capacity(candidate.roster.members.len());
        for member in candidate.roster.members {
            store.require_mls_member(&member, chain_id, self.now_ms)?;
            members.push(member.certificate.peer_id);
        }
        Ok(Some(ReconciledMlsRoom {
            local_id: candidate.base.local_id,
            version: candidate.base.version,
            creator: candidate.roster.creator,
            members,
        }))
    }

    fn load_candidate(
        &mut self,
        store: &Store,
        wire_id: Hash32,
    ) -> Result<Option<LocalRoomCandidate>, AslError> {
        let Some(base) = self.load_sealed_room(store, wire_id)? else {
            return Ok(None);
        };
        let roster = self.verify_current_roster(wire_id, &base)?;
        Ok(Some(LocalRoomCandidate { base, roster }))
    }

    fn verify_current_roster(
        &mut self,
        wire_id: Hash32,
        room: &SealedRoom,
    ) -> Result<VerifiedRoster, AslError> {
        let origin =
            RoomOrigin::from_context(wire_id, room.group.extensions(), room.provider.crypto())?;
        self.verify_roster(&origin, room.group.own_leaf_index(), room.group.members())
    }

    // This establishes the authenticated base tree only. In particular it
    // does not assert that any old leaf still has a valid device certificate.
    fn load_sealed_room(
        &self,
        store: &Store,
        wire_id: Hash32,
    ) -> Result<Option<SealedRoom>, AslError> {
        let Some(saved) = store.mls_room_for_reconciliation(wire_id)? else {
            return Ok(None);
        };
        let binding = RoomBinding {
            local_id: &saved.snapshot.local_id,
            wire_id,
            device: &self.local.peer_id,
        };
        let (provider, group, history) = restore_with_history(&binding, &saved.snapshot)?;
        if !group.is_active()
            || group.ciphersuite() != GROUP_CIPHERSUITE
            || group.pending_commit().is_some()
            || group.pending_proposals().next().is_some()
        {
            return Err(AslError::InvalidPolicyState);
        }
        let origin = RoomOrigin::from_context(wire_id, group.extensions(), provider.crypto())?;
        let mut leaves = Vec::with_capacity(saved.members.len());
        let mut peers = HashSet::new();
        for member in group.members() {
            let certificate = leaf_certificate(&CredentialWithKey::from(&member))?;
            if leaves.len() == MAX_GROUP_MEMBERS
                || !saved.members.contains(&certificate.peer_id)
                || !peers.insert(certificate.peer_id.clone())
            {
                return Err(AslError::InvalidDatabase);
            }
            leaves.push(StoredLeaf {
                member,
                certificate,
            });
        }
        if leaves.len() != saved.members.len() {
            return Err(AslError::InvalidDatabase);
        }
        let creator_index = leaves
            .iter()
            .find(|leaf| {
                leaf.certificate.peer_id == saved.creator
                    && origin.matches_creator(&leaf.certificate)
            })
            .map(|leaf| leaf.member.index)
            .ok_or(AslError::InvalidDatabase)?;
        let own = leaves
            .iter()
            .find(|leaf| {
                leaf.member.index == group.own_leaf_index() && &leaf.certificate == self.local
            })
            .ok_or(AslError::InvalidIdentity)?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &own.member.signature_key,
            GROUP_CIPHERSUITE.signature_algorithm(),
        )
        .filter(|signer| signer.public() == own.member.signature_key)
        .ok_or(AslError::InvalidDatabase)?;
        Ok(Some(SealedRoom {
            local_id: saved.snapshot.local_id,
            version: saved.snapshot.version,
            provider,
            group,
            signer,
            creator: saved.creator,
            creator_index,
            leaves,
            history,
        }))
    }
}

fn member_evidence(
    certificate: DeviceCertificate,
    record: &VerifiedRecord,
) -> Result<MlsMemberEvidence, AslError> {
    Ok(MlsMemberEvidence {
        device_key: transport_ed25519_key(&certificate.peer_id)?,
        certificate,
        registry_sequence: record.registry_state.sequence,
        controller: record.registry_state.controller,
        directory_commitment: Hash32(record.registry_state.state_commitment),
    })
}

fn check_directory_histories(
    histories: &HashMap<AgentId, RecordHistory>,
    peers: &HashMap<[u8; 16], PeerAdmission>,
    agent: AgentId,
    record: &VerifiedRecord,
) -> Result<(), AslError> {
    if let Some(history) = histories.get(&agent) {
        history.check(record)?;
    }
    for peer in peers
        .values()
        .filter(|peer| peer.admitted_agent == Some(agent))
    {
        if let Some(history) = &peer.history {
            history.check(record)?;
        }
    }
    Ok(())
}
