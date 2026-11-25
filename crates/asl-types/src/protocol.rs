mod act;
pub(crate) mod cbor;
mod expression;
mod group;
mod group_control;
mod semantic_context;

use serde::Serialize;
use serde_json::Value as Json;

use crate::{
    error::{AslError, ErrorCode},
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
};
pub use act::{
    Act, ActAction, ActType, MAX_ACT_ACTION_ARGS, MAX_ACT_ATTACHMENTS, MAX_ACT_BYTES, MAX_ACT_HOP,
    MAX_ACT_NL_BYTES,
};
pub use cbor::{
    MAX_CONTROL_FRAME_BYTES, MAX_EXTENDED_FRAME_BYTES, MAX_PAIRING_FRAME_BYTES, decode_control,
    decode_frame, encode_control, encode_frame,
};
pub use expression::{Expression, ExpressionLetter};
pub use group::{
    GroupBody, GroupMembership, GroupPacket, MAX_GROUP_MEMBERS, MAX_GROUP_MLS_OBJECT_BYTES,
    MAX_GROUP_PAYLOAD_BYTES,
};
pub use group_control::{
    GROUP_ALLOW_MEMBER_FILES, GROUP_ALLOW_MEMBER_INVITE, GROUP_ALLOW_MEMBER_TEXT,
    GROUP_ALLOWED_PERMISSION_BITS, GroupControl, MAX_GROUP_CONTROL_BYTES, MAX_GROUP_CONTROL_PEERS,
};
pub use semantic_context::{
    ContextAgreement, ContextAgreementStatus, ContextExpression, ContextOffer, ContextRequest,
    MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES, MAX_SEMANTIC_CONTEXT_CONCEPTS,
    MAX_SEMANTIC_CONTEXT_DEPENDENCIES, MAX_SEMANTIC_CONTEXT_VECTORS, SemanticConceptDefinition,
    SemanticConformanceVector, SemanticContextBundle, SemanticContextRef,
    SignedSemanticContextBundle,
};

pub const ASL_PROTOCOL_MAJOR: u16 = 1;
pub const ASL_PROTOCOL_MINOR: u16 = 3;
pub const MAX_PAIRING_NOTE_CHARS: usize = 120;
pub const MAX_PAIRING_NOTE_BYTES: usize = MAX_PAIRING_NOTE_CHARS * 4;

pub fn validate_pairing_note(note: &str) -> Result<(), AslError> {
    if note.chars().count() > MAX_PAIRING_NOTE_CHARS
        || note.len() > MAX_PAIRING_NOTE_BYTES
        || note
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(AslError::InvalidMessage);
    }

    let last_non_whitespace = note
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .map(|(index, _)| index)
        .next_back();
    let sentence_endings = [
        '.', '!', '?', '\u{037e}', '\u{0589}', '\u{061f}', '\u{06d4}', '\u{0964}', '\u{0965}',
        '\u{1362}', '\u{3002}', '\u{ff01}', '\u{ff0e}', '\u{ff1f}',
    ];
    if note.char_indices().any(|(index, character)| {
        sentence_endings.contains(&character) && Some(index) != last_non_whitespace
    }) {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feature {
    Query,
    Blob,
    Inline,
    Profile,
    ActNl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    FindEvidence,
    LocateResource,
    VerifyClaim,
    IdentifyAgent,
    OfferResource,
    GroupReview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintOperator {
    Equal,
    NotEqual,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
    Contains,
    In,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultShape {
    Claims,
    Resources,
    Agents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnswerStatus {
    Answered,
    NoMatch,
    Declined,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultStatus {
    Complete,
    Partial,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaKind {
    Other,
    Document,
    Image,
    Audio,
    Video,
    Archive,
    StructuredData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupOperation {
    Application,
    Membership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConceptRef {
    pub vocabulary_id: u16,
    pub concept_id: u32,
}

impl ConceptRef {
    pub const RUST: Self = Self {
        vocabulary_id: 1,
        concept_id: 101,
    };

    pub fn is_topic(self) -> bool {
        self.vocabulary_id == 1 && (100..=111).contains(&self.concept_id)
    }

    pub fn is_known(self) -> bool {
        self.vocabulary_id == 1 && matches!(self.concept_id, 1..=6 | 100..=111 | 200..=209)
    }

    pub fn accepts_object(self, value: &TypedValue) -> bool {
        if self.vocabulary_id != 1 {
            return false;
        }
        match self.concept_id {
            200 => true,
            201 | 202 | 205 | 206 | 209 => matches!(value, TypedValue::Integer(_)),
            203 | 204 => matches!(value, TypedValue::Concepts(_)),
            207 => matches!(value, TypedValue::Hash(_)),
            208 => matches!(value, TypedValue::Agent(_)),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedValue {
    Integer(i64),
    Boolean(bool),
    Null,
    Hash(Hash32),
    Agent(AgentId),
    Concept(ConceptRef),
    Quantity(i64, ConceptRef),
    Concepts(Vec<ConceptRef>),
}

impl TypedValue {
    pub fn from_json(value: &Json) -> Result<Self, AslError> {
        let values = value.as_array().ok_or(AslError::InvalidMessage)?;
        let kind = values
            .first()
            .and_then(Json::as_u64)
            .ok_or(AslError::InvalidMessage)?;
        match (kind, values.as_slice()) {
            (0, [_, value]) => value
                .as_i64()
                .map(Self::Integer)
                .ok_or(AslError::InvalidMessage),
            (1, [_, value]) => value
                .as_bool()
                .map(Self::Boolean)
                .ok_or(AslError::InvalidMessage),
            (2, [_, Json::Null]) => Ok(Self::Null),
            (3, [_, value]) => Ok(Self::Hash(Hash32(parse_json_hex(value)?))),
            (4, [_, value]) => Ok(Self::Agent(AgentId(parse_json_hex(value)?))),
            (5, [_, value]) => Ok(Self::Concept(concept_from_json(value)?)),
            (6, [_, value, unit]) => Ok(Self::Quantity(
                value.as_i64().ok_or(AslError::InvalidMessage)?,
                concept_from_json(unit)?,
            )),
            (7, [_, Json::Array(values)]) if values.len() <= 64 => values
                .iter()
                .map(concept_from_json)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Concepts),
            _ => Err(AslError::InvalidMessage),
        }
    }

    pub fn to_json(&self) -> Json {
        match self {
            Self::Integer(value) => serde_json::json!([0, value]),
            Self::Boolean(value) => serde_json::json!([1, value]),
            Self::Null => serde_json::json!([2, null]),
            Self::Hash(value) => serde_json::json!([3, hex::encode(value.0)]),
            Self::Agent(value) => serde_json::json!([4, hex::encode(value.0)]),
            Self::Concept(value) => serde_json::json!([5, [value.vocabulary_id, value.concept_id]]),
            Self::Quantity(value, unit) => {
                serde_json::json!([6, value, [unit.vocabulary_id, unit.concept_id]])
            }
            Self::Concepts(values) => serde_json::json!([
                7,
                values
                    .iter()
                    .map(|value| serde_json::json!([value.vocabulary_id, value.concept_id]))
                    .collect::<Vec<_>>()
            ]),
        }
    }
}

fn parse_json_hex(value: &Json) -> Result<[u8; 32], AslError> {
    let text = value.as_str().ok_or(AslError::InvalidMessage)?;
    let bytes = hex::decode(text).map_err(|_| AslError::InvalidMessage)?;
    bytes.try_into().map_err(|_| AslError::InvalidMessage)
}

fn concept_from_json(value: &Json) -> Result<ConceptRef, AslError> {
    let values = value.as_array().ok_or(AslError::InvalidMessage)?;
    if values.len() != 2 {
        return Err(AslError::InvalidMessage);
    }
    let vocabulary_id = u16::try_from(values[0].as_u64().ok_or(AslError::InvalidMessage)?)
        .map_err(|_| AslError::InvalidMessage)?;
    let concept_id = u32::try_from(values[1].as_u64().ok_or(AslError::InvalidMessage)?)
        .map_err(|_| AslError::InvalidMessage)?;
    let concept = ConceptRef {
        vocabulary_id,
        concept_id,
    };
    concept
        .is_known()
        .then_some(concept)
        .ok_or(AslError::InvalidMessage)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Constraint {
    pub predicate: ConceptRef,
    pub operator: ConstraintOperator,
    pub value: TypedValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    pub subject: TypedValue,
    pub predicate: ConceptRef,
    pub object: TypedValue,
    pub evidence: Option<Hash32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCertificate {
    pub agent_id: AgentId,
    pub peer_id: PeerId,
    pub serial: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: Signature65,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    pub message_id: Id128,
    pub agent_id: AgentId,
    pub peer_id: PeerId,
    pub device_certificate: DeviceCertificate,
    pub major: u16,
    pub minor: u16,
    pub features: Vec<Feature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    pub message_id: Id128,
    pub root_task_id: Id128,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub intent_id: Intent,
    pub topics: Vec<ConceptRef>,
    pub constraints: Vec<Constraint>,
    pub result_shape: ResultShape,
    pub budget: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer {
    pub message_id: Id128,
    pub root_task_id: Id128,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: AnswerStatus,
    pub claims: Vec<Claim>,
    pub evidence_ids: Vec<Id128>,
    pub result_status: ResultStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offer {
    pub message_id: Id128,
    pub root_task_id: Id128,
    pub content_id: Hash32,
    pub file_size: u64,
    pub media_kind: MediaKind,
    pub concepts: Vec<ConceptRef>,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchRequest {
    pub message_id: Id128,
    pub root_task_id: Id128,
    pub content_id: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchGrant {
    pub message_id: Id128,
    pub content_id: Hash32,
    pub lease_id: Hash32,
    pub expires_at_ms: u64,
    pub file_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchPending {
    pub message_id: Id128,
    pub content_id: Hash32,
    pub retry_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    pub message_id: Id128,
    pub code: ErrorCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ack {
    pub message_id: Id128,
    pub received_id: Id128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub agent_id: AgentId,
    pub sequence: u64,
    pub capabilities: Vec<ConceptRef>,
    pub avatar: Option<Hash32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityProofRequest {
    pub request_id: Id128,
    pub agent_id: AgentId,
    pub checkpoint_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProof {
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageProof {
    pub slot: [u8; 32],
    pub value: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityProof {
    pub request_id: Id128,
    pub agent_id: AgentId,
    pub finalized_height: u64,
    pub block_hash: Hash32,
    pub state_root: Hash32,
    pub account: AccountProof,
    pub storage_proofs: Vec<StorageProof>,
    pub signed_directory: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingInvite {
    pub invite_id: Id128,
    pub inviter: AgentId,
    pub target: AgentId,
    pub expires_at_ms: u64,
    pub nonce: Hash32,
    pub note: String,
    pub signature: Signature65,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingExchange {
    pub exchange_id: Id128,
    pub agent_id: AgentId,
    pub peer_id: PeerId,
    pub attempt: u8,
    pub accepted: bool,
    pub signature: Signature65,
    pub transcript_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupEnvelope {
    pub message_id: Id128,
    pub group_id: Hash32,
    pub epoch: u64,
    pub operation: GroupOperation,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireFrame {
    Hello(Hello),
    Query(Query),
    Answer(Answer),
    Offer(Offer),
    FetchRequest(FetchRequest),
    FetchGrant(FetchGrant),
    FetchPending(FetchPending),
    Error(ProtocolError),
    Ack(Ack),
    Profile(Profile),
    IdentityProofRequest(IdentityProofRequest),
    IdentityProof(IdentityProof),
    PairingInvite(PairingInvite),
    PairingExchange(PairingExchange),
    GroupEnvelope(GroupEnvelope),
    Expression(ExpressionLetter),
    ContextRequest(ContextRequest),
    ContextOffer(ContextOffer),
    ContextAgreement(ContextAgreement),
    ContextExpression(ContextExpression),
}

impl WireFrame {
    pub fn is_control(&self) -> bool {
        matches!(
            self,
            Self::Hello(_)
                | Self::Query(_)
                | Self::Answer(_)
                | Self::Offer(_)
                | Self::FetchRequest(_)
                | Self::FetchGrant(_)
                | Self::FetchPending(_)
                | Self::Error(_)
                | Self::Ack(_)
                | Self::Profile(_)
                | Self::Expression(_)
                | Self::ContextRequest(_)
                | Self::ContextOffer(_)
                | Self::ContextAgreement(_)
                | Self::ContextExpression(_)
        )
    }
}
