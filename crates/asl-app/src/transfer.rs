use std::collections::{HashMap, VecDeque};

use asl_net::codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus};
use asl_policy::{
    AccessOperation, AccessRequest, LeaseManager, Permit, PolicyEngine, PolicyRevision,
    PolicyService, Principal, fetch::issue_fetch_grant,
};
use asl_store::{
    Store,
    search::{
        direct::{DirectRequester, open_direct_store},
        group::GroupRequester,
    },
    transfers::{UploadAdmission, UploadBinding},
};
use asl_transfer::bulk::{BulkReadPlan, authorize_bulk_request};
use asl_types::{
    error::{AslError, ErrorCode},
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{FetchGrant, FetchPending, FetchRequest, ProtocolError, WireFrame},
};
use rand::{TryRng, rngs::SysRng};

use crate::{libraries::LocalLibraries, network::NetworkCommand, profile::CoreAdmission};

mod incoming;
pub use incoming::{CorruptFetchManifest, FetchManifestDetails, VerifiedFetchManifest};
use incoming::{IncomingFetchTracker, PendingManifest};

const PERMIT_LIFETIME_MS: u64 = 10_000;
const MAX_PENDING_BULK_REQUESTS: usize = 64;
const MAX_COMPLETED_BULK_RESPONSES: usize = 64;
pub(crate) const FETCH_TIMEOUT_MS: u64 =
    2 * asl_net::transport::REQUEST_TIMEOUT.as_millis() as u64 + 1_000;

pub(crate) struct TransferService {
    store: Store,
    engines: HashMap<PeerId, PolicyEngine>,
    group_engines: HashMap<(PeerId, asl_types::task::GroupId), PolicyEngine>,
    group_leases: HashMap<Hash32, GroupLease>,
    leases: LeaseManager,
    bulk_responses: BulkResponseTracker,
    incoming_fetches: IncomingFetchTracker,
}

struct GroupLease {
    requester: GroupRequester,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchedBulkResponse {
    pub connection_id: [u8; 16],
    pub agent_id: AgentId,
    pub peer_id: PeerId,
    pub request: BulkRequest,
    pub response: BulkResponse,
}

struct PendingBulkRequest {
    connection_id: [u8; 16],
    agent_id: AgentId,
    peer_id: PeerId,
    request: BulkRequest,
    expires_at_ms: u64,
    retain_until_ms: u64,
    manifest: Option<PendingManifest>,
}

struct CompletedBulkResponse {
    matched: MatchedBulkResponse,
    manifest: Option<PendingManifest>,
}

pub(crate) enum ReceivedBulk {
    Raw(MatchedBulkResponse),
    Manifest(VerifiedFetchManifest),
    CorruptManifest(CorruptFetchManifest),
}

impl CompletedBulkResponse {
    fn into_received(self) -> Option<ReceivedBulk> {
        match self.manifest {
            Some(manifest) => manifest.verify(self.matched),
            None => Some(ReceivedBulk::Raw(self.matched)),
        }
    }
}

#[derive(Default)]
struct BulkResponseTracker {
    pending: HashMap<[u8; 16], PendingBulkRequest>,
    completed: VecDeque<CompletedBulkResponse>,
}

impl BulkResponseTracker {
    fn register(
        &mut self,
        connection_id: [u8; 16],
        requester: &DirectRequester,
        request: BulkRequest,
        manifest: Option<PendingManifest>,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.expire(now_ms);
        let request_id = request.request_id.0;
        let expires_at_ms = request_deadline(requester, now_ms).min(
            manifest
                .as_ref()
                .map_or(u64::MAX, |manifest| manifest.lease_expires_at_ms),
        );
        if expires_at_ms <= now_ms || self.pending.contains_key(&request_id) {
            return Err(AslError::PolicyDenied);
        }
        if self.pending.len() >= MAX_PENDING_BULK_REQUESTS {
            return Err(AslError::QuotaExceeded);
        }
        self.pending.insert(
            request_id,
            PendingBulkRequest {
                connection_id,
                agent_id: requester.agent,
                peer_id: requester.peer.clone(),
                request,
                expires_at_ms,
                // An expired manifest cannot advance the download, but Net
                // may still report that it never sent the queued request.
                retain_until_ms: manifest.as_ref().map_or(expires_at_ms, |manifest| {
                    expires_at_ms.max(manifest.failure_expires_at_ms)
                }),
                manifest,
            },
        );
        Ok(())
    }

    fn accept(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
        response: BulkResponse,
        now_ms: u64,
    ) -> bool {
        self.expire(now_ms);
        if self.completed.len() >= MAX_COMPLETED_BULK_RESPONSES {
            return false;
        }
        let Some(pending) = self.pending.get(&request_id) else {
            return false;
        };
        if pending.connection_id != connection_id
            || pending.agent_id != agent_id
            || &pending.peer_id != peer_id
            || pending.request.request_id.0 != request_id
            || response.request_id.0 != request_id
        {
            return false;
        }
        let Some(pending) = self.pending.remove(&request_id) else {
            return false;
        };
        if pending.expires_at_ms <= now_ms {
            return false;
        }
        self.completed.push_back(CompletedBulkResponse {
            matched: MatchedBulkResponse {
                connection_id,
                agent_id,
                peer_id: peer_id.clone(),
                request: pending.request,
                response,
            },
            manifest: pending.manifest,
        });
        true
    }

    fn fail(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
        now_ms: u64,
    ) -> Option<PendingBulkRequest> {
        self.expire(now_ms);
        let pending = self.pending.get(&request_id)?;
        if pending.connection_id != connection_id
            || pending.agent_id != agent_id
            || &pending.peer_id != peer_id
            || pending.request.request_id.0 != request_id
        {
            return None;
        }
        self.pending.remove(&request_id)
    }

    fn disconnect(&mut self, connection_id: [u8; 16]) {
        self.pending
            .retain(|_, pending| pending.connection_id != connection_id);
    }

    fn expire(&mut self, now_ms: u64) {
        self.pending
            .retain(|_, pending| pending.retain_until_ms > now_ms);
    }

    fn try_recv(&mut self) -> Option<CompletedBulkResponse> {
        self.completed.pop_front()
    }

    fn cancel(&mut self, request_id: [u8; 16]) {
        self.pending.remove(&request_id);
    }
}

pub(crate) struct PreparedFetch {
    requester: DirectRequester,
    permit: Permit,
    revision: PolicyRevision,
    response: WireFrame,
    lease_id: Option<Hash32>,
    approval_id: Option<Id128>,
    content_id: Hash32,
    expires_at_ms: u64,
}

pub(crate) struct PreparedGroupFetch {
    requester: GroupRequester,
    permit: Permit,
    revision: PolicyRevision,
    response_envelope_id: Id128,
    response: WireFrame,
    lease_id: Option<Hash32>,
    approval_id: Option<Id128>,
    content_id: Hash32,
    expires_at_ms: u64,
}

pub(crate) struct PreparedBulk {
    requester: DirectRequester,
    authorization: Option<(PolicyRevision, Permit)>,
    lease_id: Hash32,
    content_id: Hash32,
    response: BulkResponse,
}

pub(crate) struct PreparedGroupBulk {
    requester: GroupRequester,
    authorization: Option<(PolicyRevision, Permit)>,
    lease_id: Hash32,
    content_id: Hash32,
    response: BulkResponse,
}

impl TransferService {
    pub(crate) fn open(database_path: &std::path::Path) -> Result<Self, AslError> {
        Ok(Self {
            store: open_direct_store(database_path)?,
            engines: HashMap::new(),
            group_engines: HashMap::new(),
            group_leases: HashMap::new(),
            leases: LeaseManager::new(),
            bulk_responses: BulkResponseTracker::default(),
            incoming_fetches: IncomingFetchTracker::default(),
        })
    }

    pub(crate) fn register_manifest_source(
        &mut self,
        admission: &mut CoreAdmission,
        manifest: &VerifiedFetchManifest,
        now_ms: u64,
    ) -> Result<(), AslError> {
        admission.register_manifest_source(&mut self.store, manifest, now_ms)
    }

    pub(crate) fn expect_fetch_response(
        &mut self,
        connection_id: [u8; 16],
        requester: &DirectRequester,
        request_id: [u8; 16],
        request: &FetchRequest,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.incoming_fetches
            .register(connection_id, requester, request_id, request, None, now_ms)
    }

    #[cfg(windows)]
    pub(crate) fn expect_group_fetch_response(
        &mut self,
        connection: [u8; 16],
        requester: &DirectRequester,
        request: &FetchRequest,
        group: (Hash32, u64),
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.incoming_fetches.register(
            connection,
            requester,
            request.message_id.0,
            request,
            Some(group),
            now_ms,
        )
    }

    pub(crate) fn pending_fetch_group(&self, id: [u8; 16]) -> Option<(Hash32, u64)> {
        self.incoming_fetches.group(id)
    }

    #[cfg(windows)]
    pub(crate) fn matches_group_reply(
        &self,
        request: Id128,
        connection: [u8; 16],
        requester: &GroupRequester,
        now: u64,
    ) -> bool {
        self.incoming_fetches.matches_group_reply(
            request.0,
            (requester.wire_id, requester.membership_epoch),
            connection,
            &requester.direct,
            now,
        )
    }

    pub(crate) fn prepare_manifest_request(
        &mut self,
        admission: &mut CoreAdmission,
        connection_id: [u8; 16],
        requester: &DirectRequester,
        request_id: [u8; 16],
        grant: &FetchGrant,
        now_ms: u64,
    ) -> Result<Option<(Id128, NetworkCommand)>, AslError> {
        let Some(pending) =
            self.incoming_fetches
                .accept_grant(connection_id, requester, request_id, grant, now_ms)
        else {
            return Ok(None);
        };
        let request_id = self.fresh_bulk_request_id()?;
        let request = BulkRequest {
            operation: BulkOperation::Manifest,
            request_id,
            content_id: grant.content_id,
            lease_id: grant.lease_id,
            chunk_index: 0,
        };
        let command = admission.authorize_bulk_command(connection_id, request.clone(), now_ms)?;
        self.bulk_responses
            .register(connection_id, requester, request, Some(pending), now_ms)?;
        Ok(Some((request_id, command)))
    }

    pub(crate) fn fail_control_request(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
    ) {
        self.incoming_fetches
            .fail(connection_id, agent_id, peer_id, request_id);
    }

    pub(crate) fn expire_pending(&mut self, now_ms: u64) {
        self.bulk_responses.expire(now_ms);
        self.incoming_fetches.expire(now_ms);
        self.group_leases
            .retain(|_, lease| lease.expires_at_ms > now_ms);
    }

    pub(crate) fn cancel_bulk_request(&mut self, request_id: [u8; 16]) {
        self.bulk_responses.cancel(request_id);
    }

    fn fresh_bulk_request_id(&self) -> Result<Id128, AslError> {
        for _ in 0..8 {
            let mut request_id = [0; 16];
            SysRng
                .try_fill_bytes(&mut request_id)
                .map_err(|_| AslError::InvalidIdentity)?;
            if request_id != [0; 16] && !self.bulk_responses.pending.contains_key(&request_id) {
                return Ok(request_id.into());
            }
        }
        Err(AslError::InvalidIdentity)
    }

    pub(crate) fn authorize_bulk_request(
        &mut self,
        admission: &mut CoreAdmission,
        connection_id: [u8; 16],
        request: BulkRequest,
        now_ms: u64,
    ) -> Result<NetworkCommand, AslError> {
        let (agent_id, _) = admission.admitted_peer_identity(connection_id, now_ms)?;
        let requester = admission
            .direct_requester(connection_id, agent_id)
            .ok_or(AslError::InvalidIdentity)?;
        let command = admission.authorize_bulk_command(connection_id, request.clone(), now_ms)?;
        self.bulk_responses
            .register(connection_id, &requester, request, None, now_ms)?;
        Ok(command)
    }

    pub(crate) fn accept_bulk_response(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
        response: BulkResponse,
        now_ms: u64,
    ) -> Option<ReceivedBulk> {
        if !self.bulk_responses.accept(
            connection_id,
            agent_id,
            peer_id,
            request_id,
            response,
            now_ms,
        ) {
            return None;
        }
        self.bulk_responses.try_recv()?.into_received()
    }

    pub(crate) fn fail_bulk_request(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: &PeerId,
        request_id: [u8; 16],
        now_ms: u64,
    ) -> Option<Id128> {
        self.bulk_responses
            .fail(connection_id, agent_id, peer_id, request_id, now_ms)?
            .manifest
            .map(|manifest| manifest.fetch_request_id)
    }

    pub(crate) fn prepare_fetch(
        &mut self,
        requester: DirectRequester,
        request: &FetchRequest,
        now_ms: u64,
        register_recipient: impl FnOnce(&mut asl_store::Store, &DirectRequester) -> Result<(), AslError>,
    ) -> Result<PreparedFetch, AslError> {
        let (revision, permit) = self.authorize_content(&requester, request.content_id, now_ms)?;
        register_recipient(&mut self.store, &requester)?;
        let admission = self.store.admit_upload(
            &UploadBinding {
                source_grant_id: permit.grant_id().0,
                grant_epoch: permit.grant_epoch(),
                content_id: request.content_id,
                target_agent_id: Some(requester.agent),
                target_peer_id: requester.peer.clone(),
                group: None,
                file_size: permit.file_size(),
            },
            now_ms,
        )?;
        let (response, lease_id, approval_id, expires_at_ms) = match admission {
            UploadAdmission::Allowed(approval_id) => {
                let engine = self
                    .engines
                    .get(&requester.peer)
                    .ok_or(AslError::InvalidPolicyState)?;
                let policy = engine.for_peer(requester.peer.clone());
                let grant = issue_fetch_grant(
                    &policy,
                    &self.leases,
                    &requester.peer,
                    request,
                    &permit,
                    permit.file_size(),
                    now_ms,
                )?;
                (
                    WireFrame::FetchGrant(grant.clone()),
                    Some(grant.lease_id),
                    approval_id,
                    grant.expires_at_ms,
                )
            }
            UploadAdmission::Pending { expires_at_ms, .. } => (
                WireFrame::FetchPending(FetchPending {
                    message_id: Id128(crate::profile::fresh_id()?),
                    content_id: request.content_id,
                    retry_at_ms: now_ms.saturating_add(5_000).min(expires_at_ms),
                    expires_at_ms,
                }),
                None,
                None,
                expires_at_ms,
            ),
            UploadAdmission::Denied => (
                WireFrame::Error(ProtocolError {
                    message_id: request.message_id,
                    code: ErrorCode::NotFound,
                }),
                None,
                None,
                permit.expires_at_ms(),
            ),
        };
        Ok(PreparedFetch {
            requester,
            permit,
            revision,
            response,
            lease_id,
            approval_id,
            content_id: request.content_id,
            expires_at_ms,
        })
    }

    pub(crate) fn finish_fetch(
        &self,
        prepared: PreparedFetch,
        now_ms: u64,
        enqueue: impl FnOnce(WireFrame, u64) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let peer_id = prepared.requester.peer.clone();
        let lease_id = prepared.lease_id;
        let result = (|| {
            let engine = self.engines.get(&peer_id).ok_or(AslError::NotFound)?;
            let policy = engine.for_peer(peer_id.clone());
            policy.revalidate(&prepared.permit, now_ms)?;
            if let Some(lease_id) = lease_id {
                self.leases
                    .validate(&policy, lease_id, &peer_id, prepared.content_id, now_ms)?;
            }
            self.store.with_current_direct_authority(
                &prepared.requester,
                prepared.revision,
                Some(&prepared.permit),
                None,
                || {
                    if let Some(approval_id) = prepared.approval_id {
                        self.store.consume_upload_approval(approval_id, now_ms)?;
                    }
                    enqueue(prepared.response, prepared.expires_at_ms)
                },
            )
        })();
        if result.is_err()
            && let Some(lease_id) = lease_id
        {
            self.leases.release(lease_id, &peer_id)?;
        }
        result
    }

    pub(crate) fn prepare_group_fetch(
        &mut self,
        requester: GroupRequester,
        request: &FetchRequest,
        now_ms: u64,
    ) -> Result<PreparedGroupFetch, AslError> {
        let (revision, permit) =
            self.authorize_group_content(&requester, request.content_id, now_ms)?;
        let admission = self.store.admit_upload(
            &UploadBinding {
                source_grant_id: permit.grant_id().0,
                grant_epoch: permit.grant_epoch(),
                content_id: request.content_id,
                target_agent_id: None,
                target_peer_id: requester.direct.peer.clone(),
                group: Some(asl_store::transfers::GroupTransferBinding {
                    group_id: requester.group_id.clone(),
                    membership_epoch: requester.membership_epoch,
                }),
                file_size: permit.file_size(),
            },
            now_ms,
        )?;
        let (response, lease_id, approval_id, expires_at_ms) = match admission {
            UploadAdmission::Allowed(approval_id) => {
                let engine = self
                    .group_engines
                    .get(&(requester.direct.peer.clone(), requester.group_id.clone()))
                    .ok_or(AslError::InvalidPolicyState)?;
                let policy =
                    engine.for_group(requester.direct.peer.clone(), requester.group_id.clone());
                let grant = issue_fetch_grant(
                    &policy,
                    &self.leases,
                    &requester.direct.peer,
                    request,
                    &permit,
                    permit.file_size(),
                    now_ms,
                )?;
                (
                    WireFrame::FetchGrant(grant.clone()),
                    Some(grant.lease_id),
                    approval_id,
                    grant.expires_at_ms,
                )
            }
            UploadAdmission::Pending { expires_at_ms, .. } => (
                WireFrame::FetchPending(FetchPending {
                    message_id: Id128(crate::profile::fresh_id()?),
                    content_id: request.content_id,
                    retry_at_ms: now_ms.saturating_add(5_000).min(expires_at_ms),
                    expires_at_ms,
                }),
                None,
                None,
                expires_at_ms,
            ),
            UploadAdmission::Denied => (
                WireFrame::Error(ProtocolError {
                    message_id: request.message_id,
                    code: ErrorCode::NotFound,
                }),
                None,
                None,
                permit.expires_at_ms(),
            ),
        };
        if let Some(lease_id) = lease_id {
            self.group_leases.insert(
                lease_id,
                GroupLease {
                    requester: requester.clone(),
                    expires_at_ms,
                },
            );
        }
        Ok(PreparedGroupFetch {
            requester,
            permit,
            revision,
            response_envelope_id: request.message_id,
            response,
            lease_id,
            approval_id,
            content_id: request.content_id,
            expires_at_ms,
        })
    }

    pub(crate) fn finish_group_fetch(
        &mut self,
        prepared: PreparedGroupFetch,
        now_ms: u64,
        enqueue: impl FnOnce(WireFrame, Id128, u64) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let peer_id = prepared.requester.direct.peer.clone();
        let lease_id = prepared.lease_id;
        let result = (|| {
            let engine = self
                .group_engines
                .get(&(peer_id.clone(), prepared.requester.group_id.clone()))
                .ok_or(AslError::NotFound)?;
            let policy = engine.for_group(peer_id.clone(), prepared.requester.group_id.clone());
            policy.revalidate(&prepared.permit, now_ms)?;
            if let Some(lease_id) = lease_id {
                self.leases
                    .validate(&policy, lease_id, &peer_id, prepared.content_id, now_ms)?;
            }
            self.store.with_current_group_authority(
                &prepared.requester,
                prepared.revision,
                Some(&prepared.permit),
                None,
                || {
                    if let Some(approval_id) = prepared.approval_id {
                        self.store.consume_upload_approval(approval_id, now_ms)?;
                    }
                    enqueue(
                        prepared.response,
                        prepared.response_envelope_id,
                        prepared.expires_at_ms,
                    )
                },
            )
        })();
        if result.is_err()
            && let Some(lease_id) = lease_id
        {
            self.group_leases.remove(&lease_id);
            self.leases.release(lease_id, &peer_id)?;
        }
        result
    }

    pub(crate) fn prepare_bulk(
        &mut self,
        libraries: &LocalLibraries,
        requester: DirectRequester,
        request: BulkRequest,
        now_ms: u64,
    ) -> PreparedBulk {
        let response_id = request.request_id;
        let authorized = self.authorize_content(&requester, request.content_id, now_ms);
        let Ok((revision, permit)) = authorized else {
            return PreparedBulk {
                requester,
                authorization: None,
                lease_id: request.lease_id,
                content_id: request.content_id,
                response: bulk_response(response_id, BulkStatus::NotFound, Vec::new()),
            };
        };
        let Some(engine) = self.engines.get(&requester.peer) else {
            return PreparedBulk {
                requester,
                authorization: None,
                lease_id: request.lease_id,
                content_id: request.content_id,
                response: bulk_response(response_id, BulkStatus::NotFound, Vec::new()),
            };
        };
        let policy = engine.for_peer(requester.peer.clone());
        let result = serve_bulk_request(
            libraries,
            &policy,
            &self.leases,
            &requester.peer,
            &request,
            now_ms,
        );
        let (status, payload) = match result {
            Ok(payload) => (BulkStatus::Success, payload),
            Err(AslError::NotFound | AslError::PolicyDenied | AslError::ExpiredMessage) => {
                (BulkStatus::NotFound, Vec::new())
            }
            Err(_) => (BulkStatus::IntegrityFailed, Vec::new()),
        };
        PreparedBulk {
            requester,
            authorization: (status == BulkStatus::Success).then_some((revision, permit)),
            lease_id: request.lease_id,
            content_id: request.content_id,
            response: bulk_response(response_id, status, payload),
        }
    }

    pub(crate) fn finish_bulk(
        &self,
        prepared: PreparedBulk,
        now_ms: u64,
        enqueue: impl FnOnce(BulkResponse) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let Some((revision, permit)) = prepared.authorization else {
            return enqueue(prepared.response);
        };
        let Some(engine) = self.engines.get(&prepared.requester.peer) else {
            return enqueue(bulk_response(
                prepared.response.request_id,
                BulkStatus::NotFound,
                Vec::new(),
            ));
        };
        let policy = engine.for_peer(prepared.requester.peer.clone());
        if policy.revalidate(&permit, now_ms).is_err()
            || self
                .leases
                .validate(
                    &policy,
                    prepared.lease_id,
                    &prepared.requester.peer,
                    prepared.content_id,
                    now_ms,
                )
                .is_err()
        {
            return enqueue(bulk_response(
                prepared.response.request_id,
                BulkStatus::NotFound,
                Vec::new(),
            ));
        }
        let response = prepared.response;
        match self.store.with_current_direct_authority(
            &prepared.requester,
            revision,
            Some(&permit),
            None,
            || enqueue(response),
        ) {
            Ok(()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn prepare_group_bulk(
        &mut self,
        libraries: &LocalLibraries,
        requester: GroupRequester,
        request: BulkRequest,
        now_ms: u64,
    ) -> PreparedGroupBulk {
        let response_id = request.request_id;
        let authorized = self.authorize_group_content(&requester, request.content_id, now_ms);
        let Ok((revision, permit)) = authorized else {
            return PreparedGroupBulk {
                requester,
                authorization: None,
                lease_id: request.lease_id,
                content_id: request.content_id,
                response: bulk_response(response_id, BulkStatus::NotFound, Vec::new()),
            };
        };
        let Some(engine) = self
            .group_engines
            .get(&(requester.direct.peer.clone(), requester.group_id.clone()))
        else {
            return PreparedGroupBulk {
                requester,
                authorization: None,
                lease_id: request.lease_id,
                content_id: request.content_id,
                response: bulk_response(response_id, BulkStatus::NotFound, Vec::new()),
            };
        };
        let policy = engine.for_group(requester.direct.peer.clone(), requester.group_id.clone());
        let result = serve_bulk_request(
            libraries,
            &policy,
            &self.leases,
            &requester.direct.peer,
            &request,
            now_ms,
        );
        let (status, payload) = match result {
            Ok(payload) => (BulkStatus::Success, payload),
            Err(AslError::NotFound | AslError::PolicyDenied | AslError::ExpiredMessage) => {
                (BulkStatus::NotFound, Vec::new())
            }
            Err(_) => (BulkStatus::IntegrityFailed, Vec::new()),
        };
        PreparedGroupBulk {
            requester,
            authorization: (status == BulkStatus::Success).then_some((revision, permit)),
            lease_id: request.lease_id,
            content_id: request.content_id,
            response: bulk_response(response_id, status, payload),
        }
    }

    pub(crate) fn finish_group_bulk(
        &self,
        prepared: PreparedGroupBulk,
        now_ms: u64,
        enqueue: impl FnOnce(BulkResponse) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let Some((revision, permit)) = prepared.authorization else {
            return enqueue(prepared.response);
        };
        let Some(engine) = self.group_engines.get(&(
            prepared.requester.direct.peer.clone(),
            prepared.requester.group_id.clone(),
        )) else {
            return enqueue(bulk_response(
                prepared.response.request_id,
                BulkStatus::NotFound,
                Vec::new(),
            ));
        };
        let policy = engine.for_group(
            prepared.requester.direct.peer.clone(),
            prepared.requester.group_id.clone(),
        );
        if policy.revalidate(&permit, now_ms).is_err()
            || self
                .leases
                .validate(
                    &policy,
                    prepared.lease_id,
                    &prepared.requester.direct.peer,
                    prepared.content_id,
                    now_ms,
                )
                .is_err()
        {
            return enqueue(bulk_response(
                prepared.response.request_id,
                BulkStatus::NotFound,
                Vec::new(),
            ));
        }
        let response = prepared.response;
        self.store.with_current_group_authority(
            &prepared.requester,
            revision,
            Some(&permit),
            None,
            || enqueue(response),
        )
    }

    pub(crate) fn connection_disconnected(
        &mut self,
        connection_id: [u8; 16],
        peer_id: Option<&PeerId>,
    ) {
        if let Some(peer_id) = peer_id {
            self.engines.remove(peer_id);
            self.group_engines
                .retain(|(group_peer, _), _| group_peer != peer_id);
            self.group_leases
                .retain(|_, lease| &lease.requester.direct.peer != peer_id);
        }
        self.bulk_responses.disconnect(connection_id);
        self.incoming_fetches.disconnect(connection_id);
    }

    pub(crate) fn group_requester_for_lease(
        &self,
        lease_id: Hash32,
        requester: &DirectRequester,
        now_ms: u64,
    ) -> Option<GroupRequester> {
        let lease = self.group_leases.get(&lease_id)?;
        (lease.expires_at_ms > now_ms
            && lease.requester.direct.agent == requester.agent
            && lease.requester.direct.peer == requester.peer)
            .then(|| lease.requester.clone())
    }

    fn authorize_content(
        &mut self,
        requester: &DirectRequester,
        content_id: Hash32,
        now_ms: u64,
    ) -> Result<(PolicyRevision, Permit), AslError> {
        let (snapshot, keys) = self.store.direct_search_snapshot(requester)?;
        let revision = snapshot.revision;
        let engine = self.refresh_engine(requester.peer.clone(), snapshot)?;
        let policy = engine.for_peer(requester.peer.clone());
        let resources = engine.snapshot()?.resources;
        for key in keys {
            let Some(resource) = resources.get(&key) else {
                continue;
            };
            if resource.content_id != content_id {
                continue;
            }
            let permit = policy.authorize(
                &AccessRequest {
                    grant_id: resource.grant_id.clone(),
                    resource_key: key,
                    principal: Principal::Agent(requester.agent),
                    operation: AccessOperation::ReadChunk,
                },
                now_ms,
            );
            match permit {
                Ok(permit) if permit.policy_revision() == revision => {
                    return Ok((revision, permit));
                }
                Ok(_) => return Err(AslError::PolicyVersionConflict),
                Err(AslError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(AslError::NotFound)
    }

    fn authorize_group_content(
        &mut self,
        requester: &GroupRequester,
        content_id: Hash32,
        now_ms: u64,
    ) -> Result<(PolicyRevision, Permit), AslError> {
        let (snapshot, keys) = self.store.group_search_snapshot(requester)?;
        let revision = snapshot.revision;
        let key = (requester.direct.peer.clone(), requester.group_id.clone());
        let engine = self.refresh_group_engine(key, snapshot)?;
        let policy = engine.for_group(requester.direct.peer.clone(), requester.group_id.clone());
        let resources = engine.snapshot()?.resources;
        for key in keys {
            let Some(resource) = resources.get(&key) else {
                continue;
            };
            if resource.content_id != content_id {
                continue;
            }
            let permit = policy.authorize(
                &AccessRequest {
                    grant_id: resource.grant_id.clone(),
                    resource_key: key,
                    principal: Principal::Agent(requester.direct.agent),
                    operation: AccessOperation::ReadChunk,
                },
                now_ms,
            );
            match permit {
                Ok(permit)
                    if permit.policy_revision() == revision
                        && permit.group_binding()
                            == Some((requester.group_id.clone(), requester.membership_epoch)) =>
                {
                    return Ok((revision, permit));
                }
                Ok(_) => return Err(AslError::PolicyVersionConflict),
                Err(AslError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(AslError::NotFound)
    }

    fn refresh_engine(
        &mut self,
        peer_id: PeerId,
        mut snapshot: asl_policy::PolicySnapshot,
    ) -> Result<&PolicyEngine, AslError> {
        let Some(engine) = self.engines.get(&peer_id) else {
            self.engines.insert(
                peer_id.clone(),
                PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?,
            );
            return self
                .engines
                .get(&peer_id)
                .ok_or(AslError::InvalidPolicyState);
        };
        let current = engine.snapshot()?;
        if current == snapshot {
            return self
                .engines
                .get(&peer_id)
                .ok_or(AslError::InvalidPolicyState);
        }
        if snapshot.revision == current.revision {
            self.engines.insert(
                peer_id.clone(),
                PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?,
            );
        } else if snapshot.revision.0 == current.revision.0.saturating_add(1) {
            for (id, previous) in &current.grants {
                if !snapshot.grants.contains_key(id) {
                    let mut revoked = previous.clone();
                    if revoked.active {
                        revoked.epoch = revoked
                            .epoch
                            .checked_add(1)
                            .ok_or(AslError::InvalidPolicyState)?;
                        revoked.active = false;
                    }
                    snapshot.grants.insert(id.clone(), revoked);
                }
            }
            self.engines
                .get(&peer_id)
                .ok_or(AslError::InvalidPolicyState)?
                .replace_snapshot(current.revision, snapshot)?;
        } else if snapshot.revision.0 > current.revision.0 {
            self.engines.insert(
                peer_id.clone(),
                PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?,
            );
        } else {
            return Err(AslError::PolicyVersionConflict);
        }
        self.engines
            .get(&peer_id)
            .ok_or(AslError::InvalidPolicyState)
    }

    fn refresh_group_engine(
        &mut self,
        key: (PeerId, asl_types::task::GroupId),
        mut snapshot: asl_policy::PolicySnapshot,
    ) -> Result<&PolicyEngine, AslError> {
        let Some(engine) = self.group_engines.get(&key) else {
            self.group_engines.insert(
                key.clone(),
                PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?,
            );
            return self
                .group_engines
                .get(&key)
                .ok_or(AslError::InvalidPolicyState);
        };
        let current = engine.snapshot()?;
        if current == snapshot {
            return self
                .group_engines
                .get(&key)
                .ok_or(AslError::InvalidPolicyState);
        }
        if snapshot.revision == current.revision {
            self.group_engines.insert(
                key.clone(),
                PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?,
            );
        } else if snapshot.revision.0 == current.revision.0.saturating_add(1) {
            for (id, previous) in &current.grants {
                if !snapshot.grants.contains_key(id) {
                    let mut revoked = previous.clone();
                    if revoked.active {
                        revoked.epoch = revoked
                            .epoch
                            .checked_add(1)
                            .ok_or(AslError::InvalidPolicyState)?;
                        revoked.active = false;
                    }
                    snapshot.grants.insert(id.clone(), revoked);
                }
            }
            self.group_engines
                .get(&key)
                .ok_or(AslError::InvalidPolicyState)?
                .replace_snapshot(current.revision, snapshot)?;
        } else if snapshot.revision.0 > current.revision.0 {
            self.group_engines.insert(
                key.clone(),
                PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?,
            );
        } else {
            return Err(AslError::PolicyVersionConflict);
        }
        self.group_engines
            .get(&key)
            .ok_or(AslError::InvalidPolicyState)
    }
}

fn request_deadline(requester: &DirectRequester, now_ms: u64) -> u64 {
    now_ms
        .saturating_add(asl_net::transport::REQUEST_TIMEOUT.as_millis() as u64)
        .min(requester.session_expires_at_ms)
}

fn serve_bulk_request(
    libraries: &LocalLibraries,
    policy: &impl PolicyService,
    leases: &LeaseManager,
    peer_id: &PeerId,
    request: &BulkRequest,
    now_ms: u64,
) -> Result<Vec<u8>, AslError> {
    leases.validate(
        policy,
        request.lease_id,
        peer_id,
        request.content_id,
        now_ms,
    )?;
    let mut snapshot = libraries.open_snapshot(request.content_id)?;
    let authorized = authorize_bulk_request(
        policy,
        leases,
        peer_id,
        request,
        snapshot.manifest_bytes(),
        now_ms,
    )?;
    match authorized.plan {
        BulkReadPlan::Manifest { .. } => Ok(snapshot.manifest_bytes().to_vec()),
        BulkReadPlan::Chunk {
            offset,
            length,
            expected_hash,
        } => {
            let bytes = snapshot.read_range(offset, length)?;
            if blake3::hash(&bytes).as_bytes() != &expected_hash {
                return Err(AslError::InvalidDatabase);
            }
            Ok(bytes)
        }
        BulkReadPlan::Inline {
            length,
            expected_file_hash,
        } => {
            let bytes = snapshot.read_range(0, length)?;
            if blake3::hash(&bytes).as_bytes() != &expected_file_hash {
                return Err(AslError::InvalidDatabase);
            }
            Ok(bytes)
        }
    }
}

fn bulk_response(
    request_id: asl_types::ids::Id128,
    status: BulkStatus,
    payload: Vec<u8>,
) -> BulkResponse {
    BulkResponse {
        request_id,
        status,
        payload,
    }
}

#[cfg(test)]
mod bulk_response_tests {
    use asl_net::codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus};
    use asl_store::search::direct::DirectRequester;
    use asl_types::{
        ids::{AgentId, Hash32, Id128, PeerId},
        manifest::{Manifest, content_id, encode_manifest},
        protocol::{FetchGrant, FetchRequest},
    };

    use super::{
        AslError, BulkResponseTracker, IncomingFetchTracker, MAX_PENDING_BULK_REQUESTS,
        ReceivedBulk,
    };

    fn peer_id(seed: u8) -> PeerId {
        let mut bytes = vec![0, 36, 8, 1, 18, 32];
        bytes.extend_from_slice(&[seed; 32]);
        PeerId::from_bytes(bytes).unwrap()
    }

    fn requester(agent: u8, peer: u8) -> DirectRequester {
        DirectRequester {
            agent: AgentId([agent; 32]),
            peer: peer_id(peer),
            session_expires_at_ms: 10_000,
            registry_sequence: 1,
            directory_commitment: [3; 32],
            controller: [4; 20],
        }
    }

    fn make_request(request_id: u8) -> BulkRequest {
        BulkRequest {
            operation: BulkOperation::Chunk,
            request_id: Id128([request_id; 16]),
            content_id: Hash32([5; 32]),
            lease_id: Hash32([6; 32]),
            chunk_index: 7,
        }
    }

    fn response(request_id: u8) -> BulkResponse {
        BulkResponse {
            request_id: Id128([request_id; 16]),
            status: BulkStatus::Success,
            payload: vec![8, 9],
        }
    }

    #[test]
    fn bulk_tracker_reports_capacity_separately_from_a_policy_failure() {
        let mut bulk = BulkResponseTracker::default();
        let source = requester(1, 2);
        let connection = [4; 16];
        let limit = u8::try_from(MAX_PENDING_BULK_REQUESTS).unwrap();
        for id in 1..=limit {
            bulk.register(connection, &source, make_request(id), None, 1_000)
                .unwrap();
        }
        let extra = make_request(limit + 1);
        assert!(matches!(
            bulk.register(connection, &source, extra.clone(), None, 1_000),
            Err(AslError::QuotaExceeded)
        ));
        bulk.cancel(make_request(1).request_id.0);
        bulk.register(connection, &source, extra, None, 1_000)
            .unwrap();
    }

    fn fetch_fixture() -> (Manifest, Vec<u8>, FetchRequest, FetchGrant) {
        let hash = *blake3::hash(b"asl").as_bytes();
        let manifest = Manifest {
            file_size: 3,
            file_hash: hash,
            chunk_hashes: vec![hash],
        };
        let encoded = encode_manifest(&manifest).unwrap();
        let request = FetchRequest {
            message_id: Id128([7; 16]),
            root_task_id: Id128([8; 16]),
            content_id: Hash32(content_id(&encoded)),
        };
        let grant = FetchGrant {
            message_id: Id128([9; 16]),
            content_id: request.content_id,
            lease_id: Hash32([10; 32]),
            expires_at_ms: 1_500,
            file_size: manifest.file_size,
        };
        (manifest, encoded, request, grant)
    }

    #[test]
    #[cfg(windows)]
    fn group_fetch_reply_matches_only_its_live_room_epoch_and_source() {
        let (_, _, fetch, _) = fetch_fixture();
        let id = fetch.message_id.0;
        let source = requester(1, 2);
        let connection = [4; 16];
        let room = Hash32([42; 32]);
        let mut tracker = IncomingFetchTracker::default();
        tracker
            .register(connection, &source, id, &fetch, Some((room, 7)), 1_000)
            .unwrap();
        assert!(!tracker.matches_group_reply(id, (Hash32([0; 32]), 7), connection, &source, 1_001));
        assert!(!tracker.matches_group_reply(id, (room, 8), connection, &source, 1_001));
        assert!(!tracker.matches_group_reply(id, (room, 7), [0; 16], &source, 1_001));
        assert!(!tracker.matches_group_reply(id, (room, 7), connection, &requester(1, 3), 1_001));
        assert!(!tracker.matches_group_reply(
            id,
            (room, 7),
            connection,
            &source,
            super::request_deadline(&source, 1_000)
        ));
        assert!(tracker.matches_group_reply(id, (room, 7), connection, &source, 1_001));
        tracker.fail(connection, source.agent, &source.peer, id);
        tracker
            .register(connection, &source, id, &fetch, None, 1_002)
            .unwrap();
        assert!(!tracker.matches_group_reply(id, (room, 7), connection, &source, 1_003));
    }

    #[test]
    fn fetch_manifest_keeps_the_original_control_request_and_root_task() {
        let (manifest, encoded, fetch, grant) = fetch_fixture();
        let source = requester(1, 2);
        let connection = [4; 16];
        let control_id = [6; 16];
        let mut fetches = IncomingFetchTracker::default();
        fetches
            .register(connection, &source, control_id, &fetch, None, 1_000)
            .unwrap();
        for wrong_id in [fetch.message_id.0, grant.message_id.0] {
            assert!(
                fetches
                    .accept_grant(connection, &source, wrong_id, &grant, 1_100)
                    .is_none()
            );
        }
        assert!(
            fetches
                .accept_grant(connection, &requester(1, 3), control_id, &grant, 1_100)
                .is_none()
        );
        let pending = fetches
            .accept_grant(connection, &source, control_id, &grant, 1_100)
            .unwrap();
        assert!(
            fetches
                .accept_grant(connection, &source, control_id, &grant, 1_100)
                .is_none()
        );

        let bulk_id = Id128([11; 16]);
        let mut bulk = BulkResponseTracker::default();
        bulk.register(
            connection,
            &source,
            BulkRequest {
                operation: BulkOperation::Manifest,
                request_id: bulk_id,
                content_id: grant.content_id,
                lease_id: grant.lease_id,
                chunk_index: 0,
            },
            Some(pending),
            1_100,
        )
        .unwrap();
        assert!(bulk.accept(
            connection,
            source.agent,
            &source.peer,
            bulk_id.0,
            BulkResponse {
                request_id: bulk_id,
                status: BulkStatus::Success,
                payload: encoded,
            },
            1_200,
        ));
        let Some(ReceivedBulk::Manifest(verified)) = bulk.try_recv().unwrap().into_received()
        else {
            panic!("expected a verified manifest");
        };
        assert_eq!(verified.fetch_request_id, Id128(control_id));
        assert_eq!(verified.fetch_generation, 1);
        assert_eq!(verified.root_task_id, fetch.root_task_id);
        assert_eq!(verified.peer_id, source.peer);
        assert_eq!(verified.content_id, fetch.content_id);
        assert_eq!(verified.lease_id, grant.lease_id);
        assert_eq!(verified.expires_at_ms, grant.expires_at_ms);
        assert_eq!(verified.manifest, manifest);
    }

    #[test]
    fn manifest_tracking_does_not_deliver_bad_content_size_or_elapsed_lease() {
        let (mut manifest, encoded, fetch, grant) = fetch_fixture();
        let source = requester(1, 2);
        let connection = [4; 16];
        manifest.file_hash = *blake3::hash(b"xyz").as_bytes();
        manifest.chunk_hashes[0] = manifest.file_hash;
        let different_content = encode_manifest(&manifest).unwrap();
        let mut malformed = encoded.clone();
        malformed[0] ^= 1;
        for (content, grant_size, payload, receive_at, corrupt) in [
            (
                fetch.content_id,
                grant.file_size + 1,
                encoded.clone(),
                1_200,
                false,
            ),
            (
                fetch.content_id,
                grant.file_size,
                different_content,
                1_200,
                false,
            ),
            (
                fetch.content_id,
                grant.file_size,
                malformed.clone(),
                1_200,
                false,
            ),
            (
                fetch.content_id,
                grant.file_size,
                encoded,
                grant.expires_at_ms,
                false,
            ),
            (
                Hash32(content_id(&malformed)),
                grant.file_size,
                malformed,
                1_200,
                true,
            ),
        ] {
            let mut fetches = IncomingFetchTracker::default();
            let mut bulk = BulkResponseTracker::default();
            let fetch = FetchRequest {
                content_id: content,
                ..fetch.clone()
            };
            let grant = FetchGrant {
                file_size: grant_size,
                content_id: content,
                ..grant.clone()
            };
            fetches
                .register(connection, &source, fetch.message_id.0, &fetch, None, 1_000)
                .unwrap();
            let pending = fetches
                .accept_grant(connection, &source, fetch.message_id.0, &grant, 1_100)
                .unwrap();
            let request_id = Id128([11; 16]);
            bulk.register(
                connection,
                &source,
                BulkRequest {
                    operation: BulkOperation::Manifest,
                    request_id,
                    content_id: grant.content_id,
                    lease_id: grant.lease_id,
                    chunk_index: 0,
                },
                Some(pending),
                1_100,
            )
            .unwrap();
            bulk.accept(
                connection,
                source.agent,
                &source.peer,
                request_id.0,
                BulkResponse {
                    request_id,
                    status: BulkStatus::Success,
                    payload,
                },
                receive_at,
            );
            let result = bulk.try_recv().and_then(|result| result.into_received());
            if corrupt {
                let Some(ReceivedBulk::CorruptManifest(result)) = result else {
                    panic!("expected a correlated corrupt manifest");
                };
                assert_eq!(result.fetch_request_id, fetch.message_id);
                assert_eq!(result.root_task_id, fetch.root_task_id);
                assert_eq!(result.content_id, content);
                assert_eq!(result.connection_id, connection);
                assert_eq!(result.agent_id, source.agent);
                assert_eq!(result.peer_id, source.peer);
                assert_eq!(result.expires_at_ms, grant.expires_at_ms);
            } else {
                assert!(result.is_none());
            }
        }
    }

    #[test]
    fn fetch_wrong_content_or_expired_grant_cannot_open_a_manifest_request() {
        let (_, _, fetch, grant) = fetch_fixture();
        let source = requester(1, 2);
        let connection = [4; 16];
        for grant in [
            FetchGrant {
                content_id: Hash32([12; 32]),
                ..grant.clone()
            },
            FetchGrant {
                expires_at_ms: 1_100,
                ..grant
            },
        ] {
            let mut fetches = IncomingFetchTracker::default();
            fetches
                .register(connection, &source, fetch.message_id.0, &fetch, None, 1_000)
                .unwrap();
            assert!(
                fetches
                    .accept_grant(connection, &source, fetch.message_id.0, &grant, 1_100)
                    .is_none()
            );
        }
    }

    #[test]
    fn expired_manifest_still_correlates_a_net_failure_during_the_fetch() {
        let (_, _, fetch, grant) = fetch_fixture();
        let source = requester(1, 2);
        let connection = [4; 16];
        let mut fetches = IncomingFetchTracker::default();
        let mut bulk = BulkResponseTracker::default();
        fetches
            .register(connection, &source, fetch.message_id.0, &fetch, None, 1_000)
            .unwrap();
        let pending = fetches
            .accept_grant(connection, &source, fetch.message_id.0, &grant, 1_100)
            .unwrap();
        let request_id = Id128([11; 16]);
        bulk.register(
            connection,
            &source,
            BulkRequest {
                operation: BulkOperation::Manifest,
                request_id,
                content_id: grant.content_id,
                lease_id: grant.lease_id,
                chunk_index: 0,
            },
            Some(pending),
            1_100,
        )
        .unwrap();
        let linked = bulk
            .fail(
                connection,
                source.agent,
                &source.peer,
                request_id.0,
                grant.expires_at_ms,
            )
            .unwrap()
            .manifest
            .unwrap();
        assert_eq!(linked.fetch_request_id, fetch.message_id);
    }

    #[test]
    fn bulk_responses_are_correlated_once_to_the_original_connection_and_identity() {
        let mut tracker = BulkResponseTracker::default();
        let requester = requester(1, 2);
        let request = make_request(3);
        tracker
            .register([4; 16], &requester, request.clone(), None, 1_000)
            .unwrap();

        assert!(!tracker.accept(
            [44; 16],
            requester.agent,
            &requester.peer,
            request.request_id.0,
            response(3),
            1_100
        ));
        assert!(!tracker.accept(
            [4; 16],
            AgentId([11; 32]),
            &requester.peer,
            request.request_id.0,
            response(3),
            1_100
        ));
        assert!(!tracker.accept(
            [4; 16],
            requester.agent,
            &peer_id(12),
            request.request_id.0,
            response(3),
            1_100
        ));
        assert!(!tracker.accept(
            [4; 16],
            requester.agent,
            &requester.peer,
            [13; 16],
            response(3),
            1_100
        ));
        assert!(!tracker.accept(
            [4; 16],
            requester.agent,
            &requester.peer,
            request.request_id.0,
            response(14),
            1_100
        ));

        assert!(tracker.accept(
            [4; 16],
            requester.agent,
            &requester.peer,
            request.request_id.0,
            response(3),
            1_100
        ));
        assert!(!tracker.accept(
            [4; 16],
            requester.agent,
            &requester.peer,
            request.request_id.0,
            response(3),
            1_200
        ));

        let matched = tracker.try_recv().unwrap().matched;
        assert_eq!(matched.connection_id, [4; 16]);
        assert_eq!(matched.agent_id, requester.agent);
        assert_eq!(matched.peer_id, requester.peer);
        assert_eq!(matched.request, request);
        assert_eq!(matched.response, response(3));
        assert!(tracker.try_recv().is_none());
    }

    #[test]
    fn bulk_failures_and_expired_responses_only_clear_the_matching_request() {
        let mut tracker = BulkResponseTracker::default();
        let mut requester = requester(1, 2);
        requester.session_expires_at_ms = 2_000;
        let request = make_request(3);
        tracker
            .register([4; 16], &requester, request.clone(), None, 1_000)
            .unwrap();

        assert!(
            tracker
                .fail(
                    [44; 16],
                    requester.agent,
                    &requester.peer,
                    request.request_id.0,
                    1_100
                )
                .is_none()
        );
        assert!(
            tracker
                .fail(
                    [4; 16],
                    requester.agent,
                    &requester.peer,
                    request.request_id.0,
                    1_100
                )
                .is_some()
        );
        assert!(
            tracker
                .fail(
                    [4; 16],
                    requester.agent,
                    &requester.peer,
                    request.request_id.0,
                    1_200
                )
                .is_none()
        );

        tracker
            .register([4; 16], &requester, make_request(15), None, 1_000)
            .unwrap();
        assert!(!tracker.accept(
            [4; 16],
            requester.agent,
            &requester.peer,
            [15; 16],
            response(15),
            2_000
        ));
        assert!(tracker.try_recv().is_none());
    }
}

#[cfg(all(test, windows))]
pub(crate) mod tests {
    mod avatar_permissions;

    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use asl_net::codec::{BulkOperation, BulkStatus};
    use asl_policy::Audience;
    use asl_types::{
        ids::{AgentId, Hash32, Id128},
        manifest::{Manifest, content_id, encode_manifest},
        protocol::{FetchRequest, WireFrame},
    };
    use rusqlite::{Connection, params};

    use super::*;
    use crate::{
        identity::DeviceIdentity, libraries::LocalLibraries, paths::AppPaths,
        supervisor::unix_time_ms,
    };

    pub(crate) struct Fixture(PathBuf);

    impl Fixture {
        pub(crate) fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("asl-transfer-send-{:032x}", rand::random::<u128>()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let root = self.0.canonicalize().unwrap();
            let base = std::env::temp_dir().canonicalize().unwrap();
            assert_eq!(root.parent(), Some(base.as_path()));
            assert_eq!(root.file_name(), self.0.file_name());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn authorized_fetch_grant_serves_imported_markdown_inline() {
        let fixture = Fixture::new();
        let paths = AppPaths::open(&fixture.path().join("home")).unwrap();
        let source = fixture.path().join("library");
        fs::create_dir(&source).unwrap();
        let bytes = b"# ASL shared note\nA locally authorized document.\n";
        fs::write(source.join("note.md"), bytes).unwrap();

        let mut libraries = LocalLibraries::open(&paths).unwrap();
        let grant = libraries
            .authorize_directory(&source, &["md".into()], &Audience::Public, 1024)
            .unwrap();
        libraries
            .import_source(&grant, Path::new("note.md"))
            .unwrap();

        let manifest = encode_manifest(&Manifest {
            file_size: bytes.len() as u64,
            file_hash: *blake3::hash(bytes).as_bytes(),
            chunk_hashes: vec![*blake3::hash(bytes).as_bytes()],
        })
        .unwrap();
        let content = Hash32(content_id(&manifest));
        assert_eq!(
            libraries.open_snapshot(content).unwrap().manifest_bytes(),
            manifest.as_slice()
        );

        let now_ms = unix_time_ms().unwrap();
        let controller = [0x22; 20];
        let directory_commitment = [0x33; 32];
        let requester = DirectRequester {
            agent: AgentId([0x11; 32]),
            peer: DeviceIdentity::generate().unwrap().peer_id(),
            session_expires_at_ms: now_ms + 60_000,
            registry_sequence: 1,
            directory_commitment,
            controller,
        };
        let agent_id = bs58::encode(requester.agent.as_bytes()).into_string();
        let database_path = paths.state().join("asl.sqlite3");
        let database = Connection::open(&database_path).unwrap();
        database
            .execute_batch(
                "INSERT INTO chain_state_cache VALUES
                    (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);",
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
                [&agent_id],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO identity_registry_states
                 (agent_id,chain_id,controller_address,state_commitment,sequence,status,
                  finalized_height,storage_proof_hash,verified_at_ms)
                 VALUES (?1,1,?2,?3,1,'active',0,zeroblob(32),0)",
                params![
                    agent_id,
                    requester.controller.as_slice(),
                    requester.directory_commitment.as_slice()
                ],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
                 certificate_serial,certificate_expires_ms,created_at_ms)
                 VALUES (?1,?2,?3,?4,1,?5,0)",
                params![
                    bs58::encode(requester.peer.as_bytes()).into_string(),
                    agent_id,
                    "11".repeat(32),
                    vec![0_u8],
                    i64::try_from(now_ms + 60_000).unwrap()
                ],
            )
            .unwrap();
        drop(database);
        let fetch = FetchRequest {
            message_id: Id128([1; 16]),
            root_task_id: Id128([2; 16]),
            content_id: content,
        };
        let mut service = TransferService::open(&database_path).unwrap();
        service
            .store
            .set_upload_mode(asl_store::transfers::UploadMode::Ask)
            .unwrap();
        let blocked = service
            .prepare_fetch(requester.clone(), &fetch, now_ms, |_, _| Ok(()))
            .unwrap();
        let approval = service.store.upload_consents().unwrap().pop().unwrap();
        assert_eq!(approval.content_id, content);
        assert_eq!(approval.target_agent_id, Some(requester.agent));
        assert_eq!(approval.target_peer_id, requester.peer);
        assert_eq!(approval.filename, "note.md");
        assert_eq!(approval.file_size, bytes.len() as u64);
        assert!(!approval.approved);
        assert_eq!(service.leases.active_count().unwrap(), 0);
        let rejected = service.prepare_bulk(
            &libraries,
            requester.clone(),
            BulkRequest {
                operation: BulkOperation::Manifest,
                request_id: Id128([0x31; 16]),
                content_id: content,
                lease_id: Hash32([0; 32]),
                chunk_index: 0,
            },
            now_ms,
        );
        let mut bulk_status = None;
        service
            .finish_bulk(rejected, now_ms, |response| {
                bulk_status = Some(response.status);
                Ok(())
            })
            .unwrap();
        assert_eq!(bulk_status, Some(BulkStatus::NotFound));
        service
            .finish_fetch(blocked, now_ms, |frame, expires_at_ms| {
                let WireFrame::FetchPending(pending) = frame else {
                    panic!("expected pending approval response")
                };
                assert_eq!(pending.content_id, content);
                assert!(pending.retry_at_ms > now_ms);
                assert_eq!(pending.expires_at_ms, approval.expires_at_ms as u64);
                assert_eq!(expires_at_ms, pending.expires_at_ms);
                Ok(())
            })
            .unwrap();
        service
            .store
            .decide_upload(approval.approval_id, true)
            .unwrap();

        let blocked = service
            .prepare_fetch(requester.clone(), &fetch, now_ms, |_, _| Ok(()))
            .unwrap();
        let mut database = Connection::open(&database_path).unwrap();
        let writer = database
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(
            service.finish_fetch(blocked, now_ms, |_, _| panic!(
                "must not disclose during contention"
            )),
            Err(AslError::PolicyVersionConflict)
        ));
        writer.rollback().unwrap();
        let prepared = service
            .prepare_fetch(requester.clone(), &fetch, now_ms, |_, _| Ok(()))
            .unwrap();

        let mut fetch_grant = None;
        service
            .finish_fetch(prepared, now_ms, |frame, expires_at_ms| {
                let WireFrame::FetchGrant(grant) = frame else {
                    panic!("expected fetch grant")
                };
                assert!(expires_at_ms > now_ms);
                fetch_grant = Some(grant);
                Ok(())
            })
            .unwrap();
        let fetch_grant = fetch_grant.expect("fetch grant was enqueued");

        let request_id = Id128([3; 16]);
        let prepared = service.prepare_bulk(
            &libraries,
            requester,
            BulkRequest {
                operation: BulkOperation::Inline,
                request_id,
                content_id: content,
                lease_id: fetch_grant.lease_id,
                chunk_index: 0,
            },
            now_ms + 1,
        );
        let mut response = None;
        service
            .finish_bulk(prepared, now_ms + 1, |value| {
                response = Some(value);
                Ok(())
            })
            .unwrap();

        let response = response.expect("bulk response was enqueued");
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, BulkStatus::Success);
        assert_eq!(response.payload, bytes);
        assert_eq!(
            blake3::hash(&response.payload).as_bytes(),
            &Manifest {
                file_size: bytes.len() as u64,
                file_hash: *blake3::hash(bytes).as_bytes(),
                chunk_hashes: vec![*blake3::hash(bytes).as_bytes()],
            }
            .file_hash
        );
        drop(libraries);
    }

    #[test]
    fn authorized_group_fetch_grant_serves_imported_markdown_inline() {
        let fixture = Fixture::new();
        let paths = AppPaths::open(&fixture.path().join("home")).unwrap();
        let source = fixture.path().join("group-library");
        fs::create_dir(&source).unwrap();
        let bytes = b"# ASL group note\nA group-authorized document.\n";
        fs::write(source.join("group.md"), bytes).unwrap();

        let group_id = asl_types::task::GroupId(Id128([0x55; 16]));
        let now_ms = unix_time_ms().unwrap();
        let requester = DirectRequester {
            agent: AgentId([0x11; 32]),
            peer: DeviceIdentity::generate().unwrap().peer_id(),
            session_expires_at_ms: now_ms + 60_000,
            registry_sequence: 1,
            directory_commitment: [0x33; 32],
            controller: [0x22; 20],
        };
        let agent_id = bs58::encode(requester.agent.as_bytes()).into_string();
        let peer_id = bs58::encode(requester.peer.as_bytes()).into_string();
        let group_text = alloy_primitives::hex::encode(group_id.0.as_bytes());
        let mut libraries = LocalLibraries::open(&paths).unwrap();
        let database_path = paths.state().join("asl.sqlite3");
        let database = Connection::open(&database_path).unwrap();
        database
            .execute_batch(
                "INSERT INTO chain_state_cache VALUES
                    (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);",
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
                [&agent_id],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO identity_registry_states
                 (agent_id,chain_id,controller_address,state_commitment,sequence,status,
                  finalized_height,storage_proof_hash,verified_at_ms)
                 VALUES (?1,1,?2,?3,1,'active',0,zeroblob(32),0)",
                params![
                    agent_id,
                    requester.controller.as_slice(),
                    requester.directory_commitment.as_slice()
                ],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
                 certificate_serial,certificate_expires_ms,created_at_ms)
                 VALUES (?1,?2,?3,?4,1,?5,0)",
                params![
                    peer_id,
                    agent_id,
                    "11".repeat(32),
                    vec![0_u8],
                    i64::try_from(now_ms + 60_000).unwrap()
                ],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
                params![peer_id, agent_id],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO asl_groups(
                     group_id,creator_peer_id,local_name,mls_epoch,membership_epoch,state,
                     created_at_ms,updated_at_ms)
                 VALUES (?1,?2,'group fixture',1,1,'active',0,0)",
                params![group_text, peer_id],
            )
            .unwrap();
        database
            .execute(
                "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
                 VALUES (?1,?2,'creator','active',0)",
                params![group_text, peer_id],
            )
            .unwrap();
        drop(database);

        let grant = libraries
            .authorize_directory(
                &source,
                &["md".into()],
                &asl_policy::Audience::Group(group_id.clone()),
                1024,
            )
            .unwrap();
        libraries
            .import_source(&grant, Path::new("group.md"))
            .unwrap();

        let manifest = encode_manifest(&Manifest {
            file_size: bytes.len() as u64,
            file_hash: *blake3::hash(bytes).as_bytes(),
            chunk_hashes: vec![*blake3::hash(bytes).as_bytes()],
        })
        .unwrap();
        let content = Hash32(content_id(&manifest));

        let mut service = TransferService::open(&database_path).unwrap();
        let group_requester = GroupRequester {
            direct: requester.clone(),
            wire_id: Hash32([0x66; 32]),
            group_id,
            membership_epoch: 1,
        };
        let (_, group_keys) = service
            .store
            .group_search_snapshot(&group_requester)
            .unwrap();
        assert!(!group_keys.is_empty());
        let fetch = FetchRequest {
            message_id: Id128([4; 16]),
            root_task_id: Id128([5; 16]),
            content_id: content,
        };
        service
            .store
            .set_upload_mode(asl_store::transfers::UploadMode::Ask)
            .unwrap();
        let pending = service
            .prepare_group_fetch(group_requester.clone(), &fetch, now_ms)
            .unwrap();
        let approval = service.store.upload_consents().unwrap().pop().unwrap();
        assert_eq!(approval.content_id, content);
        assert_eq!(approval.target_agent_id, None);
        assert_eq!(approval.target_peer_id, requester.peer);
        assert_eq!(
            approval.group,
            Some(asl_store::transfers::GroupTransferBinding {
                group_id: group_requester.group_id.clone(),
                membership_epoch: group_requester.membership_epoch,
            })
        );
        assert_eq!(service.leases.active_count().unwrap(), 0);
        assert!(service.group_leases.is_empty());
        let rejected = service.prepare_group_bulk(
            &libraries,
            group_requester.clone(),
            BulkRequest {
                operation: BulkOperation::Manifest,
                request_id: Id128([0x32; 16]),
                content_id: content,
                lease_id: Hash32([0; 32]),
                chunk_index: 0,
            },
            now_ms,
        );
        let mut bulk_status = None;
        service
            .finish_group_bulk(rejected, now_ms, |response| {
                bulk_status = Some(response.status);
                Ok(())
            })
            .unwrap();
        assert_eq!(bulk_status, Some(BulkStatus::NotFound));
        service
            .finish_group_fetch(pending, now_ms, |frame, envelope_id, expires_at_ms| {
                assert_eq!(envelope_id, fetch.message_id);
                let WireFrame::FetchPending(pending) = frame else {
                    panic!("expected pending group approval response");
                };
                assert_eq!(pending.content_id, content);
                assert!(pending.retry_at_ms > now_ms);
                assert_eq!(pending.expires_at_ms, approval.expires_at_ms as u64);
                assert_eq!(expires_at_ms, pending.expires_at_ms);
                Ok(())
            })
            .unwrap();
        service
            .store
            .decide_upload(approval.approval_id, true)
            .unwrap();

        let prepared = service
            .prepare_group_fetch(group_requester.clone(), &fetch, now_ms)
            .unwrap();
        let mut fetch_grant = None;
        service
            .finish_group_fetch(prepared, now_ms, |frame, envelope_id, _| {
                assert_eq!(envelope_id, fetch.message_id);
                let WireFrame::FetchGrant(grant) = frame else {
                    panic!("expected group fetch grant");
                };
                fetch_grant = Some(grant);
                Ok(())
            })
            .unwrap();
        let fetch_grant = fetch_grant.expect("group fetch grant was enqueued");
        let resolved = service
            .group_requester_for_lease(fetch_grant.lease_id, &requester, now_ms)
            .expect("group lease resolves the local group requester");
        assert_eq!(resolved, group_requester);

        let request_id = Id128([6; 16]);
        let prepared = service.prepare_group_bulk(
            &libraries,
            resolved,
            BulkRequest {
                operation: BulkOperation::Inline,
                request_id,
                content_id: content,
                lease_id: fetch_grant.lease_id,
                chunk_index: 0,
            },
            now_ms + 1,
        );
        let mut response = None;
        service
            .finish_group_bulk(prepared, now_ms + 1, |value| {
                response = Some(value);
                Ok(())
            })
            .unwrap();
        let response = response.expect("group bulk response was enqueued");
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, BulkStatus::Success);
        assert_eq!(response.payload, bytes);
        service.connection_disconnected([0x77; 16], Some(&requester.peer));
        assert!(
            service
                .group_requester_for_lease(fetch_grant.lease_id, &requester, now_ms + 2)
                .is_none()
        );
    }
}
