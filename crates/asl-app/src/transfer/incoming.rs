use std::{collections::HashMap, fmt, ops::Deref};

use asl_net::codec::BulkStatus;
use asl_policy::lease::LEASE_TTL_MS;
use asl_store::search::direct::DirectRequester;
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    manifest::{Manifest, decode_manifest, encoded_len_for_size},
    protocol::{FetchGrant, FetchRequest},
};

use super::{MatchedBulkResponse, request_deadline};

const MAX_PENDING_FETCHES: usize = 64;

/// A handler can inspect every correlated response field, but cannot mint an
/// event, replace its peer, or extend its lease before submitting a download.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedFetchManifest(pub(crate) FetchManifestDetails);

impl Deref for VerifiedFetchManifest {
    type Target = FetchManifestDetails;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FetchManifestDetails {
    pub fetch_request_id: Id128,
    pub root_task_id: Id128,
    pub connection_id: [u8; 16],
    pub agent_id: AgentId,
    pub peer_id: PeerId,
    pub content_id: Hash32,
    pub lease_id: Hash32,
    pub expires_at_ms: u64,
    pub manifest: Manifest,
}

impl fmt::Debug for VerifiedFetchManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedFetchManifest")
            .field("fetch_request_id", &self.fetch_request_id)
            .field("root_task_id", &self.root_task_id)
            .field("agent_id", &self.agent_id)
            .field("content_id", &self.content_id)
            .field("file_size", &self.manifest.file_size)
            .finish_non_exhaustive()
    }
}

struct PendingFetch {
    connection_id: [u8; 16],
    agent_id: AgentId,
    peer_id: PeerId,
    request: FetchRequest,
    expires_at_ms: u64,
}

pub(super) struct PendingManifest {
    fetch_request_id: Id128,
    root_task_id: Id128,
    file_size: u64,
    pub(super) lease_expires_at_ms: u64,
}

impl PendingManifest {
    pub(super) fn verify(self, matched: MatchedBulkResponse) -> Option<VerifiedFetchManifest> {
        if matched.response.status != BulkStatus::Success {
            return None;
        }
        let content_id = matched.request.content_id;
        let manifest = decode_manifest(&matched.response.payload, content_id.0).ok()?;
        if manifest.file_size != self.file_size {
            return None;
        }
        Some(VerifiedFetchManifest(FetchManifestDetails {
            fetch_request_id: self.fetch_request_id,
            root_task_id: self.root_task_id,
            connection_id: matched.connection_id,
            agent_id: matched.agent_id,
            peer_id: matched.peer_id,
            content_id,
            lease_id: matched.request.lease_id,
            expires_at_ms: self.lease_expires_at_ms,
            manifest,
        }))
    }
}

#[derive(Default)]
pub(super) struct IncomingFetchTracker {
    pending: HashMap<[u8; 16], PendingFetch>,
}

impl IncomingFetchTracker {
    pub(super) fn register(
        &mut self,
        connection_id: [u8; 16],
        requester: &DirectRequester,
        request_id: [u8; 16],
        request: &FetchRequest,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.expire(now_ms);
        let expires_at_ms = request_deadline(requester, now_ms);
        if expires_at_ms <= now_ms
            || self.pending.len() >= MAX_PENDING_FETCHES
            || self.pending.contains_key(&request_id)
        {
            return Err(AslError::PolicyDenied);
        }
        self.pending.insert(
            request_id,
            PendingFetch {
                connection_id,
                agent_id: requester.agent,
                peer_id: requester.peer.clone(),
                request: request.clone(),
                expires_at_ms,
            },
        );
        Ok(())
    }

    pub(super) fn accept_grant(
        &mut self,
        connection_id: [u8; 16],
        requester: &DirectRequester,
        request_id: [u8; 16],
        grant: &FetchGrant,
        now_ms: u64,
    ) -> Option<PendingManifest> {
        self.expire(now_ms);
        let pending = self.take(connection_id, requester.agent, &requester.peer, request_id)?;
        let expires_at_ms = grant
            .expires_at_ms
            .min(requester.session_expires_at_ms)
            .min(now_ms.saturating_add(LEASE_TTL_MS));
        if grant.content_id != pending.request.content_id
            || expires_at_ms <= now_ms
            || grant.lease_id.0 == [0; 32]
            || encoded_len_for_size(grant.file_size).is_err()
        {
            return None;
        }
        Some(PendingManifest {
            fetch_request_id: request_id.into(),
            root_task_id: pending.request.root_task_id,
            file_size: grant.file_size,
            lease_expires_at_ms: expires_at_ms,
        })
    }

    pub(super) fn fail(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
    ) {
        self.take(connection_id, agent_id, peer_id, request_id);
    }

    fn take(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
    ) -> Option<PendingFetch> {
        let pending = self.pending.get(&request_id)?;
        if pending.connection_id != connection_id
            || pending.agent_id != agent_id
            || &pending.peer_id != peer_id
        {
            return None;
        }
        self.pending.remove(&request_id)
    }

    pub(super) fn disconnect(&mut self, connection_id: [u8; 16]) {
        self.pending
            .retain(|_, pending| pending.connection_id != connection_id);
    }

    pub(super) fn expire(&mut self, now_ms: u64) {
        self.pending
            .retain(|_, pending| pending.expires_at_ms > now_ms);
    }
}
