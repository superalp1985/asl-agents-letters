#![allow(unreachable_code)]

use super::*;
use libp2p::request_response::ProtocolSupport;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub(super) struct AslBehaviour {
    admission: Admission,
    pub(super) control: request_response::Behaviour<ControlCodec>,
    pub(super) identity_proof: request_response::Behaviour<IdentityProofCodec>,
    pub(super) bulk: request_response::Behaviour<BulkCodec>,
}

#[derive(Debug)]
pub(super) enum BehaviourEvent {
    #[allow(dead_code)]
    Admission(Infallible),
    Control(request_response::Event<WireFrame, WireFrame>),
    IdentityProof(request_response::Event<IdentityProofRequest, IdentityProof>),
    Bulk(request_response::Event<BulkRequest, BulkResponse>),
}

impl From<Infallible> for BehaviourEvent {
    fn from(value: Infallible) -> Self {
        match value {}
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
    pub(super) fn new() -> Self {
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
            admission: Admission::default(),
            control: request_response(ControlCodec, CONTROL_PROTOCOL),
            identity_proof: request_response(IdentityProofCodec, IDENTITY_PROOF_PROTOCOL),
            bulk: request_response(BulkCodec, BULK_PROTOCOL),
        }
    }
}
