use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    protocol::{
        Act, Answer, ExpressionLetter, FetchGrant, FetchPending, FetchRequest, GroupBody,
        GroupControl, GroupPacket, Offer, ProtocolError, Query, WireFrame, decode_control,
        encode_control,
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
    Expression(ExpressionLetter),
    Act(Act),
    Policy(GroupControl),
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
            Self::Expression(_) => "expression",
            Self::Act(_) => "act",
            Self::Policy(_) => "policy",
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
            Self::Expression(letter) => letter.message_id,
            Self::Act(act) => act.message_id,
            Self::Policy(control) => control.message_id,
        }
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, AslError> {
        if let Ok(frame) = decode_control(plaintext) {
            return match frame {
                WireFrame::Query(query) => Ok(Self::Query(query)),
                WireFrame::Answer(answer) => Ok(Self::Answer(answer)),
                WireFrame::Offer(offer) => Ok(Self::Offer(offer)),
                WireFrame::FetchRequest(request) => Ok(Self::FetchRequest(request)),
                WireFrame::FetchGrant(grant) => Ok(Self::FetchGrant(grant)),
                WireFrame::FetchPending(pending) => Ok(Self::FetchPending(pending)),
                WireFrame::Error(error) => Ok(Self::Error(error)),
                WireFrame::Expression(letter) => Ok(Self::Expression(letter)),
                _ => Err(AslError::InvalidMessage),
            };
        }
        if let Ok(act) = Act::decode(plaintext) {
            return Ok(Self::Act(act));
        }
        GroupControl::decode(plaintext).map(Self::Policy)
    }

    pub fn encode(self) -> Result<Vec<u8>, AslError> {
        match self {
            Self::Act(act) => act.encode(),
            Self::Policy(control) => control.encode(),
            frame => encode_control(&match frame {
                Self::Query(query) => WireFrame::Query(query),
                Self::Answer(answer) => WireFrame::Answer(answer),
                Self::Offer(offer) => WireFrame::Offer(offer),
                Self::FetchRequest(request) => WireFrame::FetchRequest(request),
                Self::FetchGrant(grant) => WireFrame::FetchGrant(grant),
                Self::FetchPending(pending) => WireFrame::FetchPending(pending),
                Self::Error(error) => WireFrame::Error(error),
                Self::Expression(letter) => WireFrame::Expression(letter),
                Self::Act(_) | Self::Policy(_) => unreachable!(),
            }),
        }
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
    let (application, sender) = open_application_with_sender(candidate, provider, packet)?;
    if sender != peer_leaf {
        return Err(AslError::PolicyDenied);
    }
    Ok(application)
}

pub fn open_application_with_sender(
    candidate: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    packet: &GroupPacket,
) -> Result<(GroupApplication, LeafNodeIndex), AslError> {
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
    let Sender::Member(sender) = message.sender() else {
        return Err(AslError::PolicyDenied);
    };
    let sender = *sender;
    let ProcessedMessageContent::ApplicationMessage(application) = message.into_content() else {
        return Err(AslError::InvalidMessage);
    };
    Ok((GroupApplication::decode(&application.into_bytes())?, sender))
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

    #[test]
    fn act_application_round_trips_without_an_outer_control_frame() {
        let application = GroupApplication::Act(Act {
            message_id: Id128([1; 16]),
            conversation_id: Id128([2; 16]),
            act_type: asl_types::protocol::ActType::Inform,
            reply_to: None,
            nl_body: Some("agent-readable data".into()),
            action: None,
            attachments: vec![Hash32([3; 32])],
            causal_root: Id128([4; 16]),
            hop: 0,
            expires_at_ms: None,
        });
        let bytes = application.clone().encode().unwrap();
        assert_eq!(GroupApplication::decode(&bytes).unwrap(), application);
    }

    #[test]
    fn owner_policy_application_round_trips_without_text() {
        let application = GroupApplication::Policy(asl_types::protocol::GroupControl {
            message_id: Id128([9; 16]),
            policy_revision: 3,
            permissions: asl_types::protocol::GROUP_ALLOW_MEMBER_TEXT
                | asl_types::protocol::GROUP_ALLOW_MEMBER_FILES,
            admins: Vec::new(),
            muted: Vec::new(),
            owner: None,
        });
        let bytes = application.clone().encode().unwrap();
        assert_eq!(GroupApplication::decode(&bytes).unwrap(), application);
    }

    #[test]
    fn expression_application_round_trips_the_control_letter() {
        let mut bytes = vec![0xa7, 0, 1, 1, 15, 2, 0x50];
        bytes.extend([1; 16]);
        bytes.extend([3, 0x50]);
        bytes.extend([2; 16]);
        bytes.extend([4, 0x18, 100, 5, 0x18, 200, 6, 0x82, 0, 0x20]);

        let application = GroupApplication::decode(&bytes).unwrap();
        assert_eq!(application.kind(), "expression");
        assert_eq!(application.message_id(), Id128([1; 16]));
        assert!(matches!(
            &application,
            GroupApplication::Expression(letter) if letter.root_task_id == Id128([2; 16])
        ));
        assert_eq!(application.encode().unwrap(), bytes);
    }
}
