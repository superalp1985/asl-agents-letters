use std::collections::HashMap;

use asl_groups::membership::{read_group_message, sync_epoch_binding};
use asl_net::transport::REQUEST_TIMEOUT;
use asl_store::{Store, group_access::GroupAdminCapabilityKind, group_state::RoomVersion};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{GroupBody, GroupMembership, GroupPacket},
};
use openmls::prelude::{LeafNodeIndex, OpenMlsProvider};

use super::{
    CoreAdmission, SealedRoom,
    sync::{CommitProgress, MemberChange, SyncClock},
};
use crate::profile::admission::fresh_id;

impl CoreAdmission {
    /// Stage a removal by the current policy owner or a delegated member
    /// administrator. No network or model message calls this method. The
    /// target need not still have a live certificate.
    pub(crate) fn remove_local_mls_member(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        target: &PeerId,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
        let clock = SyncClock::inbound(
            now_ms,
            now_ms.saturating_add(REQUEST_TIMEOUT.as_millis() as u64),
        );
        if !self.local_is_current(now_ms) {
            return Err(AslError::InvalidIdentity);
        }
        let mut room = self
            .room_evidence(directories, now_ms)
            .load_sealed_room(store, wire_id)?
            .ok_or(AslError::PolicyDenied)?;
        if room.group.own_leaf_index() == room.creator_index
            && self.local_hello.peer_id != room.creator
        {
            return Err(AslError::PolicyDenied);
        }
        let owner = store
            .group_access_owner(wire_id)?
            .ok_or(AslError::PolicyDenied)?;
        if owner != self.local_hello.peer_id
            && !store.group_admin_has_capability(
                &room.local_id,
                &self.local_hello.peer_id,
                GroupAdminCapabilityKind::ManageMembers,
            )?
        {
            return Err(AslError::PolicyDenied);
        }
        let index = room
            .leaves
            .iter()
            .find(|leaf| &leaf.certificate.peer_id == target)
            .map(|leaf| leaf.member.index)
            .ok_or(AslError::NotFound)?;
        room.removal_target(index, &owner)?;
        let base = sync_epoch_binding(&room.group, room.provider.crypto())?;
        let (commit, welcome, _) = room
            .group
            .remove_members(&room.provider, &room.signer, &[index])
            .map_err(|_| AslError::InvalidPolicyState)?;
        if welcome.is_some() {
            return Err(AslError::InvalidPolicyState);
        }
        let packet = GroupPacket {
            group_id: wire_id,
            message_id: Id128(fresh_id()?),
            epoch: room.version.mls_epoch,
            body: GroupBody::Membership(GroupMembership::Commit(
                commit.to_bytes().map_err(|_| AslError::InvalidMessage)?,
            )),
        };
        read_group_message(&packet)?;
        let GroupBody::Membership(GroupMembership::Commit(ciphertext)) = &packet.body else {
            return Err(AslError::InvalidPolicyState);
        };
        room.group
            .merge_pending_commit(&room.provider)
            .map_err(|_| AslError::InvalidPolicyState)?;
        self.persist_member_change(
            store,
            room,
            MemberChange::Remove(index),
            CommitProgress {
                wire_id,
                committer: self.local_hello.peer_id.clone(),
                base,
                ciphertext,
                from: None,
            },
            directories,
            &clock,
        )
    }
}

impl SealedRoom {
    pub(super) fn removal_target(
        &self,
        index: LeafNodeIndex,
        protected: &PeerId,
    ) -> Result<&PeerId, AslError> {
        let protected_index = self
            .leaves
            .iter()
            .find(|leaf| &leaf.certificate.peer_id == protected)
            .map(|leaf| leaf.member.index)
            .ok_or(AslError::PolicyDenied)?;
        if index == protected_index
            || index == self.creator_index
            || index == self.group.own_leaf_index()
        {
            return Err(AslError::PolicyDenied);
        }
        let removed = self
            .leaves
            .iter()
            .find(|leaf| leaf.member.index == index)
            .map(|leaf| &leaf.certificate.peer_id)
            .ok_or(AslError::PolicyDenied)?;
        if removed == protected {
            return Err(AslError::PolicyDenied);
        }
        Ok(removed)
    }
}
