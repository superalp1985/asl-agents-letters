#![allow(unreachable_code)]

use super::*;
use crate::address_policy::{AddressPolicy, validate_multiaddr};
use libp2p::{
    mdns, relay,
    request_response::ProtocolSupport,
    swarm::{THandlerInEvent, dummy},
};
use std::{
    convert::Infallible,
    task::{Context, Poll},
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub(super) struct AslBehaviour {
    admission: Admission,
    discovery: DiscoveryBehaviour,
    relay: relay::client::Behaviour,
    pub(super) control: request_response::Behaviour<ControlCodec>,
    pub(super) identity_proof: request_response::Behaviour<IdentityProofCodec>,
    pub(super) bulk: request_response::Behaviour<BulkCodec>,
}

#[derive(Debug)]
pub(super) enum BehaviourEvent {
    #[allow(dead_code)]
    Admission(Infallible),
    Discovery(DiscoveryEvent),
    Relay(relay::client::Event),
    Control(request_response::Event<WireFrame, WireFrame>),
    IdentityProof(request_response::Event<IdentityProofRequest, IdentityProof>),
    Bulk(request_response::Event<BulkRequest, BulkResponse>),
}

#[derive(Debug)]
pub(super) enum DiscoveryEvent {
    Mdns(mdns::Event),
}

impl From<Infallible> for BehaviourEvent {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<DiscoveryEvent> for BehaviourEvent {
    fn from(value: DiscoveryEvent) -> Self {
        Self::Discovery(value)
    }
}

impl From<relay::client::Event> for BehaviourEvent {
    fn from(value: relay::client::Event) -> Self {
        Self::Relay(value)
    }
}

impl From<request_response::Event<WireFrame, WireFrame>> for BehaviourEvent {
    fn from(value: request_response::Event<WireFrame, WireFrame>) -> Self {
        Self::Control(value)
    }
}

impl From<request_response::Event<IdentityProofRequest, IdentityProof>> for BehaviourEvent {
    fn from(value: request_response::Event<IdentityProofRequest, IdentityProof>) -> Self {
        Self::IdentityProof(value)
    }
}

impl From<request_response::Event<BulkRequest, BulkResponse>> for BehaviourEvent {
    fn from(value: request_response::Event<BulkRequest, BulkResponse>) -> Self {
        Self::Bulk(value)
    }
}

impl AslBehaviour {
    pub(super) fn new(local_peer_id: libp2p::PeerId, relay: relay::client::Behaviour) -> Self {
        fn request_response<C: request_response::Codec + Clone + Send + 'static>(
            codec: C,
            protocol: C::Protocol,
        ) -> request_response::Behaviour<C> {
            request_response::Behaviour::with_codec(
                codec,
                [(protocol, ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(REQUEST_TIMEOUT)
                    .with_max_concurrent_streams(MAX_PROTOCOL_STREAMS_PER_PEER),
            )
        }

        Self {
            admission: Admission::new(local_peer_id, AddressPolicy::LoopbackOnly),
            discovery: DiscoveryBehaviour::new(local_peer_id),
            relay,
            control: request_response(ControlCodec, CONTROL_PROTOCOL),
            identity_proof: request_response(IdentityProofCodec, IDENTITY_PROOF_PROTOCOL),
            bulk: request_response(BulkCodec, BULK_PROTOCOL),
        }
    }

    pub(super) fn set_address_policy(&mut self, policy: AddressPolicy) -> io::Result<()> {
        self.discovery.set_address_policy(policy)?;
        self.admission.policy = policy;
        Ok(())
    }

    pub(super) fn allow_relay_endpoint(
        &mut self,
        endpoint: crate::relay::RelayEndpoint,
    ) -> io::Result<()> {
        self.admission.allow_relay_endpoint(endpoint)
    }
}

pub(super) struct DiscoveryBehaviour {
    local_peer_id: libp2p::PeerId,
    policy: AddressPolicy,
    mdns: Option<mdns::tokio::Behaviour>,
}

impl DiscoveryBehaviour {
    fn new(local_peer_id: libp2p::PeerId) -> Self {
        Self {
            local_peer_id,
            policy: AddressPolicy::LoopbackOnly,
            mdns: None,
        }
    }

    fn set_address_policy(&mut self, policy: AddressPolicy) -> io::Result<()> {
        if self.mdns.is_some() && !policy.includes_lan() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if policy.includes_lan() && self.mdns.is_none() {
            self.mdns = Some(
                mdns::tokio::Behaviour::new(mdns::Config::default(), self.local_peer_id)
                    .map_err(io::Error::other)?,
            );
        }
        self.policy = policy;
        Ok(())
    }
}

impl NetworkBehaviour for DiscoveryBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = DiscoveryEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Ok(())
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: Option<libp2p::PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: libp2p::PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: libp2p::PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        if let Some(mdns) = &mut self.mdns {
            mdns.on_swarm_event(event);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: libp2p::PeerId,
        _: ConnectionId,
        event: Infallible,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        let Some(mdns) = &mut self.mdns else {
            return Poll::Pending;
        };

        loop {
            match mdns.poll(cx) {
                Poll::Ready(ToSwarm::NewExternalAddrOfPeer { peer_id, address }) => {
                    if validate_multiaddr(self.policy, &peer_id, &address).is_ok() {
                        return Poll::Ready(ToSwarm::NewExternalAddrOfPeer { peer_id, address });
                    }
                }
                Poll::Ready(event) => {
                    return Poll::Ready(event.map_out(DiscoveryEvent::Mdns));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
