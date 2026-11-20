use std::collections::HashMap;

use asl_groups::pending_join;
use asl_store::{
    Store,
    group_state::{MlsIncomingInvite, MlsInviteEndpoints, MlsMemberEvidence},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128},
    protocol::{GroupBody, GroupMembership, GroupPacket},
};

use super::{CoreAdmission, issue_group_credential};
use crate::{identity::AgentIdentity, profile::admission::fresh_id};

impl CoreAdmission {
    /// Reserve a local approval prompt for an authenticated invite to this
    /// device. The sender cannot set the prompt text or grant access.
    pub fn receive_targeted_mls_invite(
        &mut self,
        store: &mut Store,
        connection_id: [u8; 16],
        packet: &GroupPacket,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<Option<MlsIncomingInvite>, AslError> {
        packet.validate_request()?;
        let GroupBody::Membership(GroupMembership::Invite {
            agent,
            device,
            expires_at_ms,
        }) = &packet.body
        else {
            return Err(AslError::InvalidMessage);
        };
        if *agent != self.local_hello.agent_id || device != &self.local_hello.peer_id {
            return Err(AslError::InvalidIdentity);
        }
        let (inviter, recipient) = self.mls_invite_evidence(connection_id, directories, now_ms)?;
        let invite = MlsIncomingInvite {
            id: packet.message_id,
            wire_id: packet.group_id,
            base_epoch: packet.epoch,
            inviter: inviter.certificate.agent_id,
            inviter_device: inviter.certificate.peer_id.clone(),
            recipient: *agent,
            recipient_device: device.clone(),
            expires_at_ms: *expires_at_ms,
        };
        let endpoints = self.mls_invite_endpoints(&inviter, &recipient);
        store
            .receive_verified_mls_invite(&invite, endpoints, now_ms)
            .map(|show| show.then_some(invite))
    }

    /// Call only for a decision from the local user. This creates and
    /// persists a single-use KeyPackage, but does not send a request.
    pub fn approve_targeted_mls_invite(
        &mut self,
        store: &mut Store,
        root: &AgentIdentity,
        connection_id: [u8; 16],
        invite: &MlsIncomingInvite,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let (inviter, recipient) = self.mls_invite_evidence(connection_id, directories, now_ms)?;
        let endpoints = self.mls_invite_endpoints(&inviter, &recipient);
        let (signer, credential) =
            issue_group_credential(root, invite.wire_id, &recipient.certificate, now_ms)?;
        let prepared = pending_join::prepare(invite, Id128(fresh_id()?), credential, &signer)?;
        store.save_verified_mls_join_package(
            invite,
            prepared.key,
            &prepared.sealed_package,
            endpoints,
            now_ms,
        )
    }

    /// Restore the same request after local approval. The future network
    /// driver must bind the actual send and response to this connection.
    pub fn prepare_approved_mls_join(
        &mut self,
        store: &mut Store,
        connection_id: [u8; 16],
        invite: &MlsIncomingInvite,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        let (inviter, recipient) = self.mls_invite_evidence(connection_id, directories, now_ms)?;
        let endpoints = self.mls_invite_endpoints(&inviter, &recipient);
        let (key, sealed) = store
            .verified_mls_join_package(invite, endpoints, now_ms)?
            .ok_or(AslError::PolicyDenied)?;
        let (request, _) = pending_join::restore(invite, key, &sealed)?;
        Ok(request)
    }

    fn mls_invite_evidence(
        &mut self,
        connection_id: [u8; 16],
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<(MlsMemberEvidence, MlsMemberEvidence), AslError> {
        let inviter = self.mls_target(connection_id, directories, now_ms)?;
        let local = self.local_hello.device_certificate.clone();
        let recipient = self
            .room_evidence(directories, now_ms)
            .verify_target(local)?;
        Ok((inviter, recipient))
    }

    fn mls_invite_endpoints<'a>(
        &self,
        inviter: &'a MlsMemberEvidence,
        recipient: &'a MlsMemberEvidence,
    ) -> MlsInviteEndpoints<'a> {
        MlsInviteEndpoints {
            inviter,
            recipient,
            chain_id: self.resolver.deployment().chain_id,
        }
    }
}
