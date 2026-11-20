use super::*;

impl LocalTransport {
    pub fn send_group_request(
        &mut self,
        connection: &AuthenticatedPeer,
        request: GroupPacket,
    ) -> io::Result<RequestToken> {
        self.require_live(connection)?;
        self.require_request_capacity()?;
        request.validate_request().map_err(invalid_packet)?;
        let envelope = request.clone().into_envelope().map_err(invalid_packet)?;
        // Admission allows at most one established connection for this peer.
        let peer = libp2p_peer(connection.peer_id())?;
        let group = self
            .swarm
            .behaviour_mut()
            .group
            .as_mut()
            .ok_or(io::ErrorKind::Unsupported)?;
        if !group.is_connected(&peer) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let token = RequestToken::new(connection, self.requests.next_token()?);
        let request_id = group.send_request(&peer, envelope);
        self.track_request(
            ProtocolKind::Group,
            request_id,
            connection,
            &token,
            PendingRequestKind::Group(request),
        );
        Ok(token)
    }

    pub fn send_group_response(
        &mut self,
        connection: &AuthenticatedPeer,
        token: &ResponseToken,
        response: GroupPacket,
    ) -> io::Result<()> {
        let pending = self.response_ref(connection, token, ProtocolKind::Group)?;
        let PendingResponseKind::Group { request, .. } = &pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        request.match_reply(&response).map_err(invalid_packet)?;
        let envelope = response.into_envelope().map_err(invalid_packet)?;
        let pending = self.take_response(connection, token, ProtocolKind::Group)?;
        let PendingResponseKind::Group { channel, .. } = pending.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        self.swarm
            .behaviour_mut()
            .group
            .as_mut()
            .ok_or(io::ErrorKind::Unsupported)?
            .send_response(channel, envelope)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    pub(in crate::transport) fn handle_group(
        &mut self,
        event: request_response::Event<GroupEnvelope, GroupEnvelope>,
    ) -> Option<TransportEvent> {
        use request_response::{Event, Message};

        match event {
            Event::Message {
                peer,
                connection_id,
                message:
                    Message::Request {
                        request_id,
                        request,
                        channel,
                    },
            } => {
                let connection = self.authenticated_peer(peer, connection_id)?;
                let request = GroupPacket::from_envelope(request).ok()?;
                request.validate_request().ok()?;
                let response = self.insert_response(
                    ProtocolKind::Group,
                    &connection,
                    request_id,
                    PendingResponseKind::Group {
                        request: request.clone(),
                        channel,
                    },
                )?;
                Some(TransportEvent::GroupRequest {
                    connection,
                    request,
                    response,
                })
            }
            Event::Message {
                peer,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
            } => self.complete_request(
                ProtocolKind::Group,
                peer,
                connection_id,
                request_id,
                response,
                |connection, pending, response| {
                    if let PendingRequestKind::Group(request) = &pending.kind
                        && let Ok(response) = GroupPacket::from_envelope(response)
                        && request.match_reply(&response).is_ok()
                    {
                        return TransportEvent::GroupResponse {
                            connection,
                            request: pending.token,
                            response,
                        };
                    }
                    failed_request(&pending)
                },
            ),
            Event::OutboundFailure { request_id, .. } => {
                self.fail_request(ProtocolKind::Group, request_id)
            }
            Event::InboundFailure {
                connection_id,
                request_id,
                ..
            } => {
                self.remove_inbound(ProtocolKind::Group, connection_id, request_id);
                None
            }
            Event::ResponseSent { .. } => None,
        }
    }
}

fn invalid_packet(_: asl_types::error::AslError) -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
