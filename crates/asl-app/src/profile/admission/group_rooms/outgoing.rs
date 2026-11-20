use std::collections::HashMap;

use asl_groups::{
    local_state::{RoomBinding, seal},
    membership::{RoomOrigin, read_group_message, read_key_package},
};
use asl_store::{
    Store,
    group_state::{
        MlsInviteResponse, MlsJournalEntry, MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate,
        MlsWelcomeRequest,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    protocol::{GroupBody, GroupMembership, GroupPacket, MAX_GROUP_MEMBERS},
};
use openmls::prelude::{CredentialWithKey, OpenMlsProvider};

use super::{CoreAdmission, LocalRoomCandidate};
use crate::profile::admission::fresh_id;

impl CoreAdmission {
    /// Prepare a targeted Invite for the currently admitted device. The
    /// packet is returned only after its local record has committed.
    pub fn issue_targeted_mls_invite(
        &mut self,
        store: &mut Store,
        connection_id: [u8; 16],
        wire_id: Hash32,
        expires_at_ms: u64,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        let target = self.mls_target(connection_id, directories, now_ms)?;
        let mut candidate = self.mls_creator_candidate(store, wire_id, directories, now_ms)?;
        candidate.require_room_for_add(&target)?;
        let cert = &target.certificate;
        let packet = GroupPacket {
            group_id: wire_id,
            message_id: Id128(fresh_id()?),
            epoch: candidate.version.mls_epoch,
            body: GroupBody::Membership(GroupMembership::Invite {
                agent: cert.agent_id,
                device: cert.peer_id.clone(),
                expires_at_ms,
            }),
        };
        candidate.roster.members.push(target);
        store.issue_verified_mls_invite(
            &candidate.roster.creator,
            &packet,
            candidate.version,
            &candidate.roster.members,
            self.resolver.deployment().chain_id,
            now_ms,
        )
    }

    /// Resolve a verified KeyPackage request against the durable Invite.
    /// A retry never re-applies the Add or creates a new Welcome.
    pub fn answer_mls_key_package(
        &mut self,
        store: &mut Store,
        connection_id: [u8; 16],
        request: &GroupPacket,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        let GroupBody::Membership(GroupMembership::KeyPackage { invite, .. }) = request.body else {
            return Err(AslError::InvalidMessage);
        };
        let target = self.mls_target(connection_id, directories, now_ms)?;
        let wire_id = request.group_id;
        let mut candidate = self.mls_creator_candidate(store, wire_id, directories, now_ms)?;
        let (package, package_ref) = read_key_package(request, candidate.provider.crypto())?;
        let leaf = CredentialWithKey {
            credential: package.leaf_node().credential().clone(),
            signature_key: package.leaf_node().signature_key().clone(),
        };
        self.verify_admitted_group_leaf(connection_id, wire_id, &leaf, now_ms)?;
        let chain_id = self.resolver.deployment().chain_id;
        let lookup = MlsWelcomeRequest {
            local_creator: &candidate.roster.creator,
            recipient: target.certificate.agent_id,
            device: &target.certificate.peer_id,
            packet: request,
            package_ref,
            package_expires_at_ms: package
                .life_time()
                .not_after()
                .checked_mul(1_000)
                .ok_or(AslError::InvalidMessage)?,
        };
        match store.mls_invite_response(&lookup, now_ms)? {
            Some(MlsInviteResponse::Committed(reply)) => {
                if !candidate
                    .roster
                    .members
                    .iter()
                    .any(|member| member.certificate == target.certificate)
                    || candidate.version.mls_epoch < reply.epoch
                {
                    return Err(AslError::PolicyVersionConflict);
                }
                return store.replay_verified_mls_welcome(
                    &lookup,
                    candidate.version,
                    &candidate.roster.members,
                    chain_id,
                    now_ms,
                );
            }
            Some(MlsInviteResponse::Pending) => candidate.require_room_for_add(&target)?,
            None => return Err(AslError::PolicyDenied),
        }
        let (commit, welcome, _) = candidate
            .group
            .add_members(&candidate.provider, &candidate.signer, &[package])
            .map_err(|_| AslError::InvalidMessage)?;
        let commit_packet = GroupPacket {
            group_id: wire_id,
            message_id: Id128(fresh_id()?),
            epoch: request.epoch,
            body: GroupBody::Membership(GroupMembership::Commit(
                commit.to_bytes().map_err(|_| AslError::InvalidMessage)?,
            )),
        };
        read_group_message(&commit_packet)?;
        let GroupBody::Membership(GroupMembership::Commit(commit)) = commit_packet.body else {
            return Err(AslError::InvalidPolicyState);
        };
        candidate
            .group
            .merge_pending_commit(&candidate.provider)
            .map_err(|_| AslError::InvalidMessage)?;
        let epoch = candidate.group.epoch().as_u64();
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
        let members: Vec<_> = roster
            .members
            .iter()
            .map(|member| member.certificate.peer_id.clone())
            .collect();
        let binding = RoomBinding {
            local_id: &candidate.local_id,
            wire_id,
            device: &candidate.roster.creator,
        };
        let revision = candidate
            .version
            .revision
            .checked_add(1)
            .ok_or(AslError::QuotaExceeded)?;
        let snapshot = seal(&binding, revision, &candidate.group, &candidate.provider)?;
        let welcome = welcome.to_bytes().map_err(|_| AslError::InvalidMessage)?;
        let reply = GroupPacket {
            group_id: wire_id,
            message_id: request.message_id,
            epoch,
            body: GroupBody::Membership(GroupMembership::Welcome {
                invite,
                package_ref,
                message: welcome.clone(),
            }),
        };
        request.match_reply(&reply)?;
        store.commit_verified_mls_invite_welcome(
            &lookup,
            MlsRoomUpdate {
                local_id: &candidate.local_id,
                wire_id,
                expected: candidate.version,
                mls_epoch: epoch,
                sealed_snapshot: &snapshot,
                members: &members,
                event: Some(MlsJournalEntry {
                    sender: &candidate.roster.creator,
                    kind: MlsJournalKind::Commit,
                    ciphertext: &commit,
                }),
            },
            welcome,
            &roster.members,
            chain_id,
            now_ms,
        )?;
        Ok(reply)
    }

    pub(super) fn mls_target(
        &mut self,
        connection_id: [u8; 16],
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<MlsMemberEvidence, AslError> {
        self.admitted_peer_identity(connection_id, now_ms)?;
        let certificate = self
            .peers
            .get(&connection_id)
            .and_then(|peer| peer.remote_hello.as_ref())
            .ok_or(AslError::InvalidDeviceCertificate)?
            .device_certificate
            .clone();
        self.room_evidence(directories, now_ms)
            .verify_target(certificate)
    }

    fn mls_creator_candidate(
        &mut self,
        store: &Store,
        wire_id: Hash32,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<LocalRoomCandidate, AslError> {
        let candidate = self
            .room_evidence(directories, now_ms)
            .load_candidate(store, wire_id)?
            .ok_or(AslError::PolicyDenied)?;
        if candidate.roster.creator != self.local_hello.peer_id
            || candidate.roster.creator_index != candidate.group.own_leaf_index()
        {
            return Err(AslError::PolicyDenied);
        }
        Ok(candidate)
    }
}

impl LocalRoomCandidate {
    fn require_room_for_add(&self, target: &MlsMemberEvidence) -> Result<(), AslError> {
        if self.roster.members.len() >= MAX_GROUP_MEMBERS {
            return Err(AslError::QuotaExceeded);
        }
        if self
            .roster
            .members
            .iter()
            .any(|member| member.certificate.peer_id == target.certificate.peer_id)
        {
            return Err(AslError::PolicyDenied);
        }
        Ok(())
    }
}
