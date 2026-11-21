use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    protocol::{
        Answer, FetchGrant, FetchPending, FetchRequest, GroupBody, GroupPacket, Offer,
        ProtocolError, Query, WireFrame, decode_control, encode_control,
    },
};
use openmls::prelude::{LeafNodeIndex, MlsGroup, OpenMlsProvider, ProcessedMessageContent, Sender};
use openmls_basic_credential::SignatureKeyPair;

use crate::membership::{GROUP_CIPHERSUITE, read_group_message};

/// The only ASL messages carried inside MLS application data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupApplication {
    Query(Query),
    Answer(Answer),
    Offer(Offer),
    FetchRequest(FetchRequest),
    FetchGrant(FetchGrant),
    FetchPending(FetchPending),
    Error(ProtocolError),
}

impl GroupApplication {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Query(_) => "query",
            Self::Answer(_) => "answer",
            Self::Offer(_) => "offer",
            Self::FetchRequest(_) => "fetch_request",
            Self::FetchGrant(_) => "fetch_grant",
            Self::FetchPending(_) => "fetch_pending",
            Self::Error(_) => "error",
        }
    }

    pub fn message_id(&self) -> Id128 {
        match self {
            Self::Query(query) => query.message_id,
            Self::Answer(answer) => answer.message_id,
            Self::Offer(offer) => offer.message_id,
            Self::FetchRequest(request) => request.message_id,
            Self::FetchGrant(grant) => grant.message_id,
            Self::FetchPending(pending) => pending.message_id,
            Self::Error(error) => error.message_id,
        }
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, AslError> {
        match decode_control(plaintext)? {
            WireFrame::Query(query) => Ok(Self::Query(query)),
            WireFrame::Answer(answer) => Ok(Self::Answer(answer)),
            WireFrame::Offer(offer) => Ok(Self::Offer(offer)),
            WireFrame::FetchRequest(request) => Ok(Self::FetchRequest(request)),
            WireFrame::FetchGrant(grant) => Ok(Self::FetchGrant(grant)),
            WireFrame::FetchPending(pending) => Ok(Self::FetchPending(pending)),
            WireFrame::Error(error) => Ok(Self::Error(error)),
            _ => Err(AslError::InvalidMessage),
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, AslError> {
        encode_control(&match self {
            Self::Query(query) => WireFrame::Query(query),
            Self::Answer(answer) => WireFrame::Answer(answer),
            Self::Offer(offer) => WireFrame::Offer(offer),
            Self::FetchRequest(request) => WireFrame::FetchRequest(request),
            Self::FetchGrant(grant) => WireFrame::FetchGrant(grant),
            Self::FetchPending(pending) => WireFrame::FetchPending(pending),
            Self::Error(error) => WireFrame::Error(error),
        })
    }
}

/// Encrypt once on a disposable room candidate. The caller must validate room
/// authority and persist the advanced ratchet before fanning out the packet.
/// `envelope_id` is a fresh local correlation ID, not a replay key.
pub fn encrypt_application(
    candidate: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    envelope_id: Id128,
    payload: GroupApplication,
) -> Result<GroupPacket, AslError> {
    let group_id = Hash32(
        candidate
            .group_id()
            .as_slice()
            .try_into()
            .map_err(|_| AslError::InvalidPolicyState)?,
    );
    if candidate.ciphersuite() != GROUP_CIPHERSUITE
        || group_id.0 == [0; 32]
        || envelope_id.0 == [0; 16]
        || signer.signature_scheme() != GROUP_CIPHERSUITE.signature_algorithm()
        || candidate
            .own_leaf_node()
            .is_none_or(|leaf| leaf.signature_key().as_slice() != signer.public())
    {
        return Err(AslError::InvalidPolicyState);
    }
    let plaintext = payload.encode()?;
    let encrypted = candidate
        .create_message(provider, signer, &plaintext)
        .map_err(|_| AslError::InvalidPolicyState)?;
    let packet = GroupPacket {
        group_id,
        epoch: candidate.epoch().as_u64(),
        message_id: envelope_id,
        body: GroupBody::Application(encrypted.to_bytes().map_err(|_| AslError::InvalidMessage)?),
    };
    packet.validate_request()?;
    Ok(packet)
}

/// Decrypt only in the candidate's current epoch. `peer_leaf` must come from
/// the caller's verified roster and authenticated transport, not the packet.
/// Discard the candidate on any error; it may already have advanced its
/// receive ratchet. Do not deliver plaintext before durable commit.
pub fn open_application(
    candidate: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    peer_leaf: LeafNodeIndex,
    packet: &GroupPacket,
) -> Result<GroupApplication, AslError> {
    if !matches!(&packet.body, GroupBody::Application(_))
        || packet.group_id.as_bytes() != candidate.group_id().as_slice()
        || packet.epoch != candidate.epoch().as_u64()
        || candidate.ciphersuite() != GROUP_CIPHERSUITE
    {
        return Err(AslError::InvalidMessage);
    }
    let message = candidate
        .process_message(provider, read_group_message(packet)?)
        .map_err(|_| AslError::InvalidMessage)?;
    if message.sender() != &Sender::Member(peer_leaf) {
        return Err(AslError::PolicyDenied);
    }
    let ProcessedMessageContent::ApplicationMessage(application) = message.into_content() else {
        return Err(AslError::InvalidMessage);
    };
    GroupApplication::decode(&application.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(hex: &str) -> Vec<u8> {
        hex.split_ascii_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    #[test]
    fn application_reuses_canonical_semantic_frames_only() {
        for (index, hex) in [
            include_str!("../../../schemas/vectors/query-v1.hex"),
            include_str!("../../../schemas/vectors/answer-v1.hex"),
            include_str!("../../../schemas/vectors/offer-v1.hex"),
            include_str!("../../../schemas/vectors/fetch-request-v1.hex"),
            include_str!("../../../schemas/vectors/fetch-grant-v1.hex"),
            include_str!("../../../schemas/vectors/fetch-pending-v1.hex"),
            include_str!("../../../schemas/vectors/error-v1.hex"),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = fixture(hex);
            let message = GroupApplication::decode(&bytes).unwrap();
            assert!(matches!(
                (&message, index),
                (GroupApplication::Query(_), 0)
                    | (GroupApplication::Answer(_), 1)
                    | (GroupApplication::Offer(_), 2)
                    | (GroupApplication::FetchRequest(_), 3)
                    | (GroupApplication::FetchGrant(_), 4)
                    | (GroupApplication::FetchPending(_), 5)
                    | (GroupApplication::Error(_), 6)
            ));
            assert_eq!(message.encode().unwrap(), bytes);
        }
        for bytes in [
            fixture(include_str!("../../../schemas/vectors/ack-v1.hex")),
            fixture(include_str!(
                "../../../schemas/vectors/group-envelope-v1.hex"
            )),
            vec![0x62, b'h', b'i'],
        ] {
            assert!(GroupApplication::decode(&bytes).is_err());
        }
    }
}
