//! Local Core boundary for attested MLS rooms. None of these operations
//! activates a room, opens the group substream or grants access to files.

use std::collections::{HashMap, HashSet, hash_map::Entry};

use asl_groups::{
    local_state::{RoomBinding, RoomProvider, restore, seal},
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
        verify_record,
    },
};

use super::{CoreAdmission, PeerAdmission};

/// Only a local consistency result. The room remains `needs_sync` and
/// future operations must recheck the versions and authorization evidence.
pub struct ReconciledMlsRoom {
    pub local_id: GroupId,
    pub version: RoomVersion,
    pub creator: PeerId,
    pub members: Vec<PeerId>,
}

pub struct ApprovedMlsWelcome<'a> {
    pub connection_id: [u8; 16],
    pub invite: &'a MlsIncomingInvite,
    pub reply: &'a GroupPacket,
    pub local_id: &'a GroupId,
    pub local_name: &'a str,
    /// Core supplies locally collected signed device directories, not an
    /// unverified directory bundle from the Welcome or from a model.
    pub directories: &'a HashMap<AgentId, Vec<u8>>,
}

impl CoreAdmission {
    /// Replace an expiring local directory only after verifying the current
    /// registry and the exact existing Hello device. Rotation is not renewal.
    pub fn renew_local_mls_directory(
        &mut self,
        signed_directory: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let agent = self.local_hello.agent_id;
        let verified = verify_record(&signed_directory, agent, now_ms, &mut self.resolver)?;
        let RecordPayload::DeviceDirectory(directory) = &verified.signed().record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if !directory
            .devices
            .contains(&self.local_hello.device_certificate)
        {
            return Err(AslError::InvalidDeviceCertificate);
        }
        check_directory_histories(&self.dht_histories, &self.peers, agent, &verified)?;
        self.dht_histories
            .get_mut(&agent)
            .ok_or(AslError::InvalidPolicyState)?
            .observe(&verified)?;
        self.local_signed_directory = signed_directory;
        Ok(())
    }

    /// Create a closed room from the local identity. The local device must
    /// already be durably registered against a verified device directory.
    pub fn create_local_mls_room(
        &mut self,
        store: &mut Store,
        root: &AgentIdentity,
        local_id: &GroupId,
        local_name: &str,
        now_ms: u64,
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
        let version = store.create_mls_room(
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
    pub fn finish_approved_mls_welcome(
        &mut self,
        store: &mut Store,
        welcome: ApprovedMlsWelcome<'_>,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
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
        let sealed = seal(&binding, 1, &group, &provider)?;
        store.finish_mls_join(
            MlsJoinedRoom {
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
            },
            now_ms,
        )
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
            histories: &self.dht_histories,
            peers: &self.peers,
            resolver: &mut self.resolver,
            now_ms,
        }
    }
}

struct VerifiedRoster {
    creator: PeerId,
    creator_index: LeafNodeIndex,
    members: Vec<MlsMemberEvidence>,
    local_signature_key: Vec<u8>,
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
}

struct RoomEvidence<'a> {
    local: &'a DeviceCertificate,
    local_directory: &'a [u8],
    directories: &'a HashMap<AgentId, Vec<u8>>,
    histories: &'a HashMap<AgentId, RecordHistory>,
    peers: &'a HashMap<[u8; 16], PeerAdmission>,
    resolver: &'a mut dyn IdentityResolver,
    now_ms: u64,
}

impl RoomEvidence<'_> {
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
        let mut local_signature_key = None;
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
                Entry::Vacant(entry) => {
                    let bytes = if cert.agent_id == self.local.agent_id {
                        self.local_directory
                    } else {
                        self.directories
                            .get(&cert.agent_id)
                            .ok_or(AslError::InvalidIdentity)?
                    };
                    let record = verify_record(bytes, cert.agent_id, self.now_ms, self.resolver)?;
                    check_directory_histories(self.histories, self.peers, cert.agent_id, &record)?;
                    entry.insert(record)
                }
            };
            verify_directory_leaf(origin.wire_id(), &leaf, &cert, directory)?;
            if origin.matches_creator(&cert) {
                creator = Some((cert.peer_id.clone(), member.index));
            }
            if member.index == own_index {
                local_signature_key = Some(member.signature_key);
            }
            roster.push(MlsMemberEvidence {
                certificate: cert,
                registry_sequence: directory.registry_state.sequence,
                controller: directory.registry_state.controller,
                directory_commitment: Hash32(directory.registry_state.state_commitment),
            });
        }
        let (creator, creator_index) = creator.ok_or(AslError::PolicyDenied)?;
        Ok(VerifiedRoster {
            creator,
            creator_index,
            members: roster,
            local_signature_key: local_signature_key.ok_or(AslError::InvalidIdentity)?,
        })
    }

    fn reconcile(
        &mut self,
        store: &Store,
        wire_id: Hash32,
        chain_id: u64,
    ) -> Result<Option<ReconciledMlsRoom>, AslError> {
        let Some(saved) = store.mls_room_for_reconciliation(wire_id)? else {
            return Ok(None);
        };
        let binding = RoomBinding {
            local_id: &saved.snapshot.local_id,
            wire_id,
            device: &self.local.peer_id,
        };
        let (provider, group) = restore(&binding, &saved.snapshot)?;
        if !group.is_active()
            || group.ciphersuite() != GROUP_CIPHERSUITE
            || group.pending_commit().is_some()
        {
            return Err(AslError::InvalidPolicyState);
        }
        let origin = RoomOrigin::from_context(wire_id, group.extensions(), provider.crypto())?;
        let roster = self.verify_roster(&origin, group.own_leaf_index(), group.members())?;
        if roster.creator != saved.creator
            || roster.members.len() != saved.members.len()
            || !roster
                .members
                .iter()
                .all(|member| saved.members.contains(&member.certificate.peer_id))
        {
            return Err(AslError::InvalidDatabase);
        }
        let mut members = Vec::with_capacity(roster.members.len());
        for member in roster.members {
            store.require_mls_member(&member, chain_id, self.now_ms)?;
            members.push(member.certificate.peer_id);
        }
        if SignatureKeyPair::read(
            provider.storage(),
            &roster.local_signature_key,
            GROUP_CIPHERSUITE.signature_algorithm(),
        )
        .is_none_or(|signer| signer.public() != roster.local_signature_key)
        {
            return Err(AslError::InvalidDatabase);
        }
        Ok(Some(ReconciledMlsRoom {
            local_id: saved.snapshot.local_id,
            version: saved.snapshot.version,
            creator: roster.creator,
            members,
        }))
    }
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
