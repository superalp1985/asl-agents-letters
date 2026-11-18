use super::*;

pub(super) struct Requests {
    inbound: HashMap<ResponseToken, PendingResponse>,
    outbound: HashMap<(ProtocolKind, OutboundRequestId), PendingRequest>,
    queued_events: VecDeque<TransportEvent>,
    next_token: Option<u64>,
}

impl Requests {
    pub(super) fn new() -> Self {
        Self {
            inbound: HashMap::new(),
            outbound: HashMap::new(),
            queued_events: VecDeque::new(),
            next_token: Some(1),
        }
    }

    fn next_token(&mut self) -> io::Result<u64> {
        let token = self.next_token.ok_or(io::ErrorKind::Other)?;
        self.next_token = token.checked_add(1);
        Ok(token)
    }

    pub(super) fn pop_event(&mut self) -> Option<TransportEvent> {
        self.queued_events.pop_front()
    }

    pub(super) fn close_connection(&mut self, connection_id: LocalConnectionId) {
        self.inbound.retain(|token, _| token.0 != connection_id);
        self.outbound.retain(|_, pending| {
            if pending.connection_id == connection_id {
                self.queued_events.push_back(failed_request(pending));
                false
            } else {
                true
            }
        });
    }
}

impl LocalTransport {
    pub fn send_control_request(
        &mut self,
        connection: &AuthenticatedPeer,
        request: WireFrame,
    ) -> io::Result<RequestToken> {
        self.require_live(connection)?;
        self.require_request_capacity()?;
        if !request.is_control() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let token = RequestToken(self.requests.next_token()?);
        let request_id = self
            .swarm
            .behaviour_mut()
            .control
            .send_request(&libp2p_peer(connection.peer_id())?, request);
        self.track_request(
            ProtocolKind::Control,
            request_id,
            connection,
            token,
            PendingRequestKind::Control,
        );
        Ok(token)
    }

    pub fn send_identity_proof_request(
        &mut self,
        connection: &AuthenticatedPeer,
        request: IdentityProofRequest,
    ) -> io::Result<RequestToken> {
        self.require_live(connection)?;
        self.require_request_capacity()?;
        let token = RequestToken(self.requests.next_token()?);
        let request_id = self
            .swarm
            .behaviour_mut()
            .identity_proof
            .send_request(&libp2p_peer(connection.peer_id())?, request.clone());
        self.track_request(
            ProtocolKind::IdentityProof,
            request_id,
            connection,
            token,
            PendingRequestKind::IdentityProof(request),
        );
        Ok(token)
    }

    pub fn send_bulk_request(
        &mut self,
        connection: &AuthenticatedPeer,
        request: BulkRequest,
    ) -> io::Result<RequestToken> {
        self.require_live(connection)?;
        self.require_request_capacity()?;
        let token = RequestToken(self.requests.next_token()?);
        let request_id = self
            .swarm
            .behaviour_mut()
            .bulk
            .send_request(&libp2p_peer(connection.peer_id())?, request.clone());
        self.track_request(
            ProtocolKind::Bulk,
            request_id,
            connection,
            token,
            PendingRequestKind::Bulk(request),
        );
        Ok(token)
    }

    pub fn send_control_response(
        &mut self,
        connection: &AuthenticatedPeer,
        token: ResponseToken,
        response: WireFrame,
    ) -> io::Result<()> {
        if !response.is_control() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let pending = self.take_response(connection, token, ProtocolKind::Control)?;
        let PendingResponseKind::Control(channel) = pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        self.swarm
            .behaviour_mut()
            .control
            .send_response(channel, response)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    pub fn send_identity_proof_response(
        &mut self,
        connection: &AuthenticatedPeer,
        token: ResponseToken,
        response: IdentityProof,
    ) -> io::Result<()> {
        let pending = self.response_ref(connection, token, ProtocolKind::IdentityProof)?;
        let PendingResponseKind::IdentityProof { request, .. } = &pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if response.request_id != request.request_id
            || response.agent_id != request.agent_id
            || response.block_hash != request.checkpoint_hash
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let pending = self.take_response(connection, token, ProtocolKind::IdentityProof)?;
        let PendingResponseKind::IdentityProof { channel, .. } = pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        self.swarm
            .behaviour_mut()
            .identity_proof
            .send_response(channel, response)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    pub fn send_bulk_response(
        &mut self,
        connection: &AuthenticatedPeer,
        token: ResponseToken,
        response: BulkResponse,
    ) -> io::Result<()> {
        let pending = self.response_ref(connection, token, ProtocolKind::Bulk)?;
        let PendingResponseKind::Bulk { request, .. } = &pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if response.request_id != request.request_id {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let pending = self.take_response(connection, token, ProtocolKind::Bulk)?;
        let PendingResponseKind::Bulk { channel, .. } = pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        self.swarm
            .behaviour_mut()
            .bulk
            .send_response(channel, response)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn require_live(&self, connection: &AuthenticatedPeer) -> io::Result<()> {
        if !connection.is_live()
            || self
                .live
                .get(&connection.connection_id)
                .is_none_or(|owner| !Weak::ptr_eq(&Arc::downgrade(owner), &connection.lifetime))
        {
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(())
    }

    fn require_request_capacity(&self) -> io::Result<()> {
        if self.requests.outbound.len() >= MAX_PENDING_REQUESTS {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    }

    fn track_request(
        &mut self,
        protocol: ProtocolKind,
        request_id: OutboundRequestId,
        connection: &AuthenticatedPeer,
        token: RequestToken,
        kind: PendingRequestKind,
    ) {
        self.requests.outbound.insert(
            (protocol, request_id),
            PendingRequest {
                token,
                connection_id: connection.connection_id,
                kind,
            },
        );
    }

    fn take_response(
        &mut self,
        connection: &AuthenticatedPeer,
        token: ResponseToken,
        protocol: ProtocolKind,
    ) -> io::Result<PendingResponse> {
        self.response_ref(connection, token, protocol)?;
        self.requests
            .inbound
            .remove(&token)
            .ok_or(io::ErrorKind::NotFound.into())
    }

    fn response_ref(
        &self,
        connection: &AuthenticatedPeer,
        token: ResponseToken,
        protocol: ProtocolKind,
    ) -> io::Result<&PendingResponse> {
        self.require_live(connection)?;
        if token.0 != connection.connection_id {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let pending = self
            .requests
            .inbound
            .get(&token)
            .ok_or(io::ErrorKind::NotFound)?;
        if pending.protocol != protocol {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(pending)
    }

    pub(super) fn handle_control(
        &mut self,
        event: request_response::Event<WireFrame, WireFrame>,
    ) -> io::Result<Option<TransportEvent>> {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
            } => {
                let Some(connection) = self.authenticated_peer(peer, connection_id) else {
                    return Ok(None);
                };
                let Some(response) = self.insert_response(
                    ProtocolKind::Control,
                    connection.connection_id,
                    request_id,
                    PendingResponseKind::Control(channel),
                ) else {
                    return Ok(None);
                };
                Ok(Some(TransportEvent::ControlRequest {
                    connection,
                    request,
                    response,
                }))
            }
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => Ok(self.complete_request(
                ProtocolKind::Control,
                peer,
                connection_id,
                request_id,
                response,
                |connection, pending, response| {
                    if matches!(&pending.kind, PendingRequestKind::Control) {
                        TransportEvent::ControlResponse {
                            connection,
                            request: pending.token,
                            response,
                        }
                    } else {
                        failed_request(&pending)
                    }
                },
            )),
            request_response::Event::OutboundFailure { request_id, .. } => {
                Ok(self.fail_request(ProtocolKind::Control, request_id))
            }
            request_response::Event::InboundFailure {
                connection_id,
                request_id,
                ..
            } => {
                self.remove_inbound(ProtocolKind::Control, connection_id, request_id);
                Ok(None)
            }
            request_response::Event::ResponseSent { .. } => Ok(None),
        }
    }

    pub(super) fn handle_identity_proof(
        &mut self,
        event: request_response::Event<IdentityProofRequest, IdentityProof>,
    ) -> io::Result<Option<TransportEvent>> {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
            } => {
                let Some(connection) = self.authenticated_peer(peer, connection_id) else {
                    return Ok(None);
                };
                let Some(response) = self.insert_response(
                    ProtocolKind::IdentityProof,
                    connection.connection_id,
                    request_id,
                    PendingResponseKind::IdentityProof {
                        channel,
                        request: request.clone(),
                    },
                ) else {
                    return Ok(None);
                };
                Ok(Some(TransportEvent::IdentityProofRequest {
                    connection,
                    request,
                    response,
                }))
            }
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => Ok(self.complete_request(
                ProtocolKind::IdentityProof,
                peer,
                connection_id,
                request_id,
                response,
                |connection, pending, response| {
                    let valid = matches!(
                        &pending.kind,
                        PendingRequestKind::IdentityProof(request)
                            if response.request_id == request.request_id
                                && response.agent_id == request.agent_id
                                && response.block_hash == request.checkpoint_hash
                    );
                    if valid {
                        TransportEvent::IdentityProofResponse {
                            connection,
                            request: pending.token,
                            response,
                        }
                    } else {
                        failed_request(&pending)
                    }
                },
            )),
            request_response::Event::OutboundFailure { request_id, .. } => {
                Ok(self.fail_request(ProtocolKind::IdentityProof, request_id))
            }
            request_response::Event::InboundFailure {
                connection_id,
                request_id,
                ..
            } => {
                self.remove_inbound(ProtocolKind::IdentityProof, connection_id, request_id);
                Ok(None)
            }
            request_response::Event::ResponseSent { .. } => Ok(None),
        }
    }

    pub(super) fn handle_bulk(
        &mut self,
        event: request_response::Event<BulkRequest, BulkResponse>,
    ) -> io::Result<Option<TransportEvent>> {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
            } => {
                let Some(connection) = self.authenticated_peer(peer, connection_id) else {
                    return Ok(None);
                };
                let Some(response) = self.insert_response(
                    ProtocolKind::Bulk,
                    connection.connection_id,
                    request_id,
                    PendingResponseKind::Bulk {
                        channel,
                        request: request.clone(),
                    },
                ) else {
                    return Ok(None);
                };
                Ok(Some(TransportEvent::BulkRequest {
                    connection,
                    request,
                    response,
                }))
            }
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => Ok(self.complete_request(
                ProtocolKind::Bulk,
                peer,
                connection_id,
                request_id,
                response,
                |connection, pending, response| {
                    let valid = matches!(
                        &pending.kind,
                        PendingRequestKind::Bulk(request)
                            if response.request_id == request.request_id
                    );
                    if valid {
                        TransportEvent::BulkResponse {
                            connection,
                            request: pending.token,
                            response,
                        }
                    } else {
                        failed_request(&pending)
                    }
                },
            )),
            request_response::Event::OutboundFailure { request_id, .. } => {
                Ok(self.fail_request(ProtocolKind::Bulk, request_id))
            }
            request_response::Event::InboundFailure {
                connection_id,
                request_id,
                ..
            } => {
                self.remove_inbound(ProtocolKind::Bulk, connection_id, request_id);
                Ok(None)
            }
            request_response::Event::ResponseSent { .. } => Ok(None),
        }
    }

    fn authenticated_peer(
        &self,
        peer: libp2p::PeerId,
        connection_id: ConnectionId,
    ) -> Option<AuthenticatedPeer> {
        let connection_id = LocalConnectionId(connection_id);
        let owner = self.live.get(&connection_id)?;
        Some(AuthenticatedPeer {
            peer: device_peer(peer).ok()?,
            connection_id,
            lifetime: Arc::downgrade(owner),
        })
    }

    fn insert_response(
        &mut self,
        protocol: ProtocolKind,
        connection_id: LocalConnectionId,
        inbound_request_id: InboundRequestId,
        response: PendingResponseKind,
    ) -> Option<ResponseToken> {
        if self.requests.inbound.len() >= MAX_PENDING_RESPONSES {
            return None;
        }
        let token = ResponseToken(connection_id, self.requests.next_token().ok()?);
        self.requests.inbound.insert(
            token,
            PendingResponse {
                kind: response,
                protocol,
                inbound_request_id,
            },
        );
        Some(token)
    }

    fn complete_request<R>(
        &mut self,
        protocol: ProtocolKind,
        peer: libp2p::PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        response: R,
        event: impl FnOnce(AuthenticatedPeer, PendingRequest, R) -> TransportEvent,
    ) -> Option<TransportEvent> {
        let pending = self.requests.outbound.remove(&(protocol, request_id))?;
        let connection_id = LocalConnectionId(connection_id);
        if pending.connection_id != connection_id {
            return Some(failed_request(&pending));
        }
        Some(match self.authenticated_peer(peer, connection_id.0) {
            Some(connection) => event(connection, pending, response),
            None => failed_request(&pending),
        })
    }

    fn fail_request(
        &mut self,
        protocol: ProtocolKind,
        request_id: OutboundRequestId,
    ) -> Option<TransportEvent> {
        let pending = self.requests.outbound.remove(&(protocol, request_id))?;
        Some(failed_request(&pending))
    }

    fn remove_inbound(
        &mut self,
        protocol: ProtocolKind,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
    ) {
        let connection_id = LocalConnectionId(connection_id);
        self.requests.inbound.retain(|token, pending| {
            pending.protocol != protocol
                || token.0 != connection_id
                || pending.inbound_request_id != request_id
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ProtocolKind {
    Control,
    IdentityProof,
    Bulk,
}

struct PendingResponse {
    kind: PendingResponseKind,
    protocol: ProtocolKind,
    inbound_request_id: InboundRequestId,
}

enum PendingResponseKind {
    Control(ResponseChannel<WireFrame>),
    IdentityProof {
        channel: ResponseChannel<IdentityProof>,
        request: IdentityProofRequest,
    },
    Bulk {
        channel: ResponseChannel<BulkResponse>,
        request: BulkRequest,
    },
}

enum PendingRequestKind {
    Control,
    IdentityProof(IdentityProofRequest),
    Bulk(BulkRequest),
}

struct PendingRequest {
    token: RequestToken,
    connection_id: LocalConnectionId,
    kind: PendingRequestKind,
}

fn failed_request(pending: &PendingRequest) -> TransportEvent {
    TransportEvent::RequestFailed {
        connection_id: pending.connection_id,
        request: pending.token,
    }
}

fn libp2p_peer(peer: &PeerId) -> io::Result<libp2p::PeerId> {
    libp2p::PeerId::from_bytes(peer.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput.into())
}
