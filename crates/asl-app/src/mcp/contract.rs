use std::collections::BTreeMap;

use asl_agent::QueryScope;
use asl_store::budgets::BudgetKind;
use asl_transfer::scheduler::MAX_ACTIVE_SOURCES;
use asl_types::{
    error::ErrorCode,
    ids::{AgentId, Hash32, Id128},
    protocol::{
        Act, ActAction, ActType, ConceptRef, ContextExpression, Expression, Intent,
        MAX_ACT_ACTION_ARGS, MAX_ACT_ATTACHMENTS, MAX_ACT_NL_BYTES,
        MAX_SEMANTIC_CONTEXT_DEPENDENCIES, MediaKind, ResultShape, SemanticContextRef, TypedValue,
        WireFrame, encode_control,
    },
};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum ServerFrame {
    AgentEvent { event: Value },
    AgentEventLoss { dropped: u64 },
    Reply(Result<Value, ErrorCode>),
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct EmptyArgs {}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActHistorySearchArgs {
    #[schemars(length(min = 1, max = 256))]
    pub query: String,
    #[schemars(range(min = 1, max = 100))]
    pub limit: Option<u32>,
}

impl ActHistorySearchArgs {
    pub(super) fn validate(self) -> Result<(String, u32), ErrorCode> {
        if self.query.is_empty() || self.query.len() > 256 || self.query.as_bytes().contains(&0) {
            return Err(ErrorCode::InvalidMessage);
        }
        let limit = self.limit.unwrap_or(25);
        if !(1..=100).contains(&limit) {
            return Err(ErrorCode::InvalidMessage);
        }
        Ok((self.query, limit))
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Query(QueryArgs),
    TaskStatus(TaskArgs),
    Fetch(FetchArgs),
    Result(TaskArgs),
    AgentEventsAvailable,
    SubscribeAgentEvents,
    UnsubscribeAgentEvents,
    LocalCapabilities,
    AgentBootstrap,
    ActHistorySearch(ActHistorySearchArgs),
    ContactLookup(AgentTargetArgs),
    ContactStatus,
    SendExpression(ExpressionArgs),
    SendContextExpression(ContextExpressionArgs),
    SendAct(ActArgs),
    SendShardAnnouncement(ActArgs),
    SendFile(SendFileArgs),
    GroupList,
    GroupCreate,
    GroupMembers(GroupRoomArgs),
    GroupSetAccess(GroupSetAccessArgs),
    GroupInvite(GroupInviteArgs),
    GroupInviteRequest(GroupInviteRequestArgs),
    GroupRejectJoinRequest(GroupRejectJoinRequestArgs),
    DirectOpen(AgentTargetArgs),
    RenewActBudget(RenewActBudgetArgs),
    RenewResourceBudget(RenewResourceBudgetArgs),
    RequestContext(ContextRequestArgs),
    ConfirmContext(ConfirmContextArgs),
    ReceiveOffer(ReceiveOfferArgs),
    RecoveryTask(TaskArgs),
    RecoveryEvents(RecoveryEventsArgs),
    RecoveryQuery(RecoveryQueryArgs),
    RecoveryResult(TaskArgs),
    RecoveryDownload(RecoveryDownloadArgs),
    RecoveryDownloadDecision(RecoveryDownloadDecisionArgs),
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryDownloadDecisionArgs {
    #[schemars(length(equal = 32))]
    pub approval_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryDownloadArgs {
    #[schemars(length(equal = 32))]
    pub transfer_id: String,
    pub resume: bool,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryQueryArgs {
    #[schemars(length(equal = 32))]
    pub request_id: String,
    #[schemars(range(min = 1))]
    pub valid_until_ms: i64,
    pub request: QueryArgs,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryEventsArgs {
    #[schemars(range(min = 0))]
    pub after: i64,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ExpressionArgs {
    #[schemars(regex(pattern = r"^(agent|group):[a-fA-F0-9]{64}$"))]
    pub target: String,
    #[schemars(length(equal = 32))]
    pub root: Option<String>,
    pub expression: Vec<Value>,
}

impl ExpressionArgs {
    pub(super) fn validate(self) -> Result<(String, Option<Id128>, Expression), ErrorCode> {
        let (kind, id) = self
            .target
            .split_once(':')
            .ok_or(ErrorCode::InvalidMessage)?;
        if !matches!(kind, "agent" | "group")
            || id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ErrorCode::InvalidMessage);
        }
        let root = self.root.as_deref().map(parse_id).transpose()?;
        let expression = Expression::from_json(&Value::Array(self.expression))
            .map_err(|_| ErrorCode::InvalidMessage)?;
        Ok((self.target, root, expression))
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextExpressionArgs {
    #[schemars(regex(pattern = r"^(agent|group):[a-fA-F0-9]{64}$"))]
    pub target: String,
    #[schemars(length(equal = 32))]
    pub root: Option<String>,
    pub expression: Vec<Value>,
    #[schemars(length(min = 1, max = MAX_SEMANTIC_CONTEXT_DEPENDENCIES))]
    pub required_contexts: Vec<ContextRefArgs>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextRefArgs {
    #[schemars(length(equal = 64))]
    pub authority: String,
    pub namespace: u32,
    #[schemars(range(min = 1))]
    pub revision: u16,
    #[schemars(length(equal = 64))]
    pub digest: String,
}

impl ContextExpressionArgs {
    pub(super) fn validate(
        self,
    ) -> Result<(String, Option<Id128>, Expression, Vec<SemanticContextRef>), ErrorCode> {
        let (kind, id) = self
            .target
            .split_once(':')
            .ok_or(ErrorCode::InvalidMessage)?;
        if !matches!(kind, "agent" | "group")
            || id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ErrorCode::InvalidMessage);
        }
        let root = self.root.as_deref().map(parse_id).transpose()?;
        let expression = Expression::from_json(&Value::Array(self.expression))
            .map_err(|_| ErrorCode::InvalidMessage)?;
        let required_contexts = self
            .required_contexts
            .into_iter()
            .map(|reference| {
                Ok(SemanticContextRef {
                    authority: AgentId(
                        alloy_primitives::hex::decode_to_array(&reference.authority)
                            .map_err(|_| ErrorCode::InvalidMessage)?,
                    ),
                    namespace: reference.namespace,
                    revision: reference.revision,
                    digest: Hash32(
                        alloy_primitives::hex::decode_to_array(&reference.digest)
                            .map_err(|_| ErrorCode::InvalidMessage)?,
                    ),
                })
            })
            .collect::<Result<Vec<_>, ErrorCode>>()?;
        let probe = WireFrame::ContextExpression(ContextExpression {
            message_id: Id128([1; 16]),
            root_task_id: Id128([2; 16]),
            created_at_ms: 0,
            expires_at_ms: 1,
            required_contexts: required_contexts.clone(),
            expression: expression.clone(),
        });
        encode_control(&probe).map_err(|_| ErrorCode::InvalidMessage)?;
        Ok((self.target, root, expression, required_contexts))
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
    #[schemars(length(equal = 32))]
    pub message_id: Option<String>,
    #[schemars(length(equal = 32))]
    pub conversation_id: Option<String>,
    pub act_type: String,
    #[schemars(length(equal = 32))]
    pub reply_to: Option<String>,
    #[schemars(length(min = 1, max = MAX_ACT_NL_BYTES))]
    pub nl_body: Option<String>,
    pub action: Option<ActActionArgs>,
    #[schemars(length(max = MAX_ACT_ATTACHMENTS))]
    pub attachments: Vec<String>,
    #[schemars(length(equal = 32))]
    pub causal_root: Option<String>,
    #[schemars(range(min = 0))]
    pub hop: Option<u32>,
    #[schemars(range(min = 1))]
    pub expires_at_ms: Option<u64>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActActionArgs {
    pub vocabulary_id: u16,
    pub concept_id: u32,
    #[schemars(length(max = MAX_ACT_ACTION_ARGS))]
    pub args: Vec<ActArgumentArgs>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActArgumentArgs {
    pub key: u32,
    pub value: Vec<Value>,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SendFileArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
    #[schemars(length(equal = 64))]
    pub content_id: String,
    pub media_kind: String,
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub concepts: Vec<(u16, u32)>,
}

impl SendFileArgs {
    pub(super) fn validate(
        self,
    ) -> Result<(Hash32, Hash32, MediaKind, Vec<ConceptRef>), ErrorCode> {
        let room = parse_hash32(&self.room)?;
        let content_id = parse_hash32(&self.content_id)?;
        let media_kind = match self.media_kind.as_str() {
            "other" => MediaKind::Other,
            "document" => MediaKind::Document,
            "image" => MediaKind::Image,
            "audio" => MediaKind::Audio,
            "video" => MediaKind::Video,
            "archive" => MediaKind::Archive,
            "structured_data" => MediaKind::StructuredData,
            _ => return Err(ErrorCode::InvalidMessage),
        };
        if self.concepts.len() > 16 {
            return Err(ErrorCode::InvalidMessage);
        }
        let concepts = self
            .concepts
            .into_iter()
            .map(|(vocabulary_id, concept_id)| {
                let concept = ConceptRef {
                    vocabulary_id,
                    concept_id,
                };
                concept
                    .is_topic()
                    .then_some(concept)
                    .ok_or(ErrorCode::InvalidMessage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((room, content_id, media_kind, concepts))
    }
}

fn parse_hash32(value: &str) -> Result<Hash32, ErrorCode> {
    alloy_primitives::hex::decode_to_array(value)
        .map(Hash32)
        .map_err(|_| ErrorCode::InvalidMessage)
}

impl ActArgs {
    pub(super) fn validate(self) -> Result<(Hash32, Act), ErrorCode> {
        let room = Hash32(
            alloy_primitives::hex::decode_to_array(&self.room)
                .map_err(|_| ErrorCode::InvalidMessage)?,
        );
        let message_id = self
            .message_id
            .as_deref()
            .map(parse_id)
            .transpose()?
            .unwrap_or(Id128([0; 16]));
        let conversation_id = self
            .conversation_id
            .as_deref()
            .map(parse_id)
            .transpose()?
            .unwrap_or(Id128([0; 16]));
        let act_type = match self.act_type.as_str() {
            "inform" => ActType::Inform,
            "ask" => ActType::Ask,
            "request" => ActType::Request,
            "propose" => ActType::Propose,
            "accept" => ActType::Accept,
            "reject" => ActType::Reject,
            "commit" => ActType::Commit,
            "cancel" => ActType::Cancel,
            "ack" => ActType::Ack,
            "clarify" => ActType::Clarify,
            _ => return Err(ErrorCode::InvalidMessage),
        };
        let reply_to = self.reply_to.as_deref().map(parse_id).transpose()?;
        let action = self
            .action
            .map(|action| {
                let mut args = BTreeMap::new();
                for argument in action.args {
                    if args
                        .insert(
                            argument.key,
                            TypedValue::from_json(&Value::Array(argument.value))
                                .map_err(|_| ErrorCode::InvalidMessage)?,
                        )
                        .is_some()
                    {
                        return Err(ErrorCode::InvalidMessage);
                    }
                }
                Ok(ActAction {
                    action_id: ConceptRef {
                        vocabulary_id: action.vocabulary_id,
                        concept_id: action.concept_id,
                    },
                    args,
                })
            })
            .transpose()?;
        let attachments = self
            .attachments
            .iter()
            .map(|attachment| {
                alloy_primitives::hex::decode_to_array(attachment)
                    .map(Hash32)
                    .map_err(|_| ErrorCode::InvalidMessage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let causal_root = self
            .causal_root
            .as_deref()
            .map(parse_id)
            .transpose()?
            .unwrap_or(Id128([0; 16]));
        Ok((
            room,
            Act {
                message_id,
                conversation_id,
                act_type,
                reply_to,
                nl_body: self.nl_body,
                action,
                attachments,
                causal_root,
                hop: self.hop.unwrap_or(0),
                expires_at_ms: self.expires_at_ms,
            },
        ))
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupInviteArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
    #[schemars(regex(pattern = r"^agent:[a-fA-F0-9]{64}$"))]
    pub target: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupInviteRequestArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
    #[schemars(regex(pattern = r"^agent:[a-fA-F0-9]{64}$"))]
    pub owner: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupRejectJoinRequestArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
    pub device: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupRoomArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
}

impl GroupRoomArgs {
    pub(super) fn validate(self) -> Result<Hash32, ErrorCode> {
        parse_hash32(&self.room)
    }
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupSetAccessArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: String,
    pub allow_member_text: bool,
    pub allow_member_files: bool,
    pub allow_member_invite: bool,
    #[schemars(length(max = 512))]
    pub admins: Vec<String>,
    #[schemars(length(max = 512))]
    pub muted: Vec<String>,
    pub owner: Option<String>,
    #[serde(default)]
    #[schemars(length(max = 512))]
    pub file_policies: Option<Vec<GroupFilePolicyArgs>>,
    #[serde(default)]
    #[schemars(length(max = 512))]
    pub admin_capabilities: Option<Vec<GroupAdminCapabilityArgs>>,
}

impl GroupSetAccessArgs {
    pub(super) fn validate(
        self,
    ) -> Result<(Hash32, crate::agent_mail::GroupAccessUpdate), ErrorCode> {
        let room = parse_hash32(&self.room)?;
        if self.admins.len() > 512 || self.muted.len() > 512 {
            return Err(ErrorCode::InvalidMessage);
        }
        let admins = self
            .admins
            .iter()
            .map(|peer| parse_peer(peer))
            .collect::<Result<Vec<_>, _>>()?;
        let muted = self
            .muted
            .iter()
            .map(|peer| parse_peer(peer))
            .collect::<Result<Vec<_>, _>>()?;
        let file_policies = self
            .file_policies
            .map(|policies| {
                policies
                    .into_iter()
                    .map(|policy| {
                        Ok(asl_types::protocol::GroupFilePolicy {
                            content_id: parse_hash32(&policy.content_id)?,
                            permissions: policy.permissions,
                        })
                    })
                    .collect::<Result<Vec<_>, ErrorCode>>()
            })
            .transpose()?;
        let admin_capabilities = self
            .admin_capabilities
            .map(|capabilities| {
                capabilities
                    .into_iter()
                    .map(|capability| {
                        Ok(asl_types::protocol::GroupAdminCapability {
                            peer: parse_peer(&capability.peer)?,
                            capabilities: capability.capabilities,
                        })
                    })
                    .collect::<Result<Vec<_>, ErrorCode>>()
            })
            .transpose()?;
        Ok((
            room,
            crate::agent_mail::GroupAccessUpdate {
                allow_member_text: self.allow_member_text,
                allow_member_files: self.allow_member_files,
                allow_member_invite: self.allow_member_invite,
                admins,
                muted,
                owner: self.owner.as_deref().map(parse_peer).transpose()?,
                file_policies,
                admin_capabilities,
            },
        ))
    }
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupFilePolicyArgs {
    #[schemars(length(equal = 64))]
    pub content_id: String,
    pub permissions: u8,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupAdminCapabilityArgs {
    pub peer: String,
    pub capabilities: u8,
}

fn parse_peer(value: &str) -> Result<asl_types::ids::PeerId, ErrorCode> {
    let peer: libp2p_identity::PeerId = value.parse().map_err(|_| ErrorCode::InvalidMessage)?;
    asl_types::ids::PeerId::from_bytes(peer.to_bytes()).map_err(|_| ErrorCode::InvalidMessage)
}

impl GroupInviteArgs {
    pub(super) fn validate(self) -> Result<(Hash32, AgentId), ErrorCode> {
        let room = Hash32(
            alloy_primitives::hex::decode_to_array(&self.room)
                .map_err(|_| ErrorCode::InvalidMessage)?,
        );
        let (kind, target) = self
            .target
            .split_once(':')
            .ok_or(ErrorCode::InvalidMessage)?;
        if kind != "agent" {
            return Err(ErrorCode::InvalidMessage);
        }
        let agent = AgentId(
            alloy_primitives::hex::decode_to_array(target)
                .map_err(|_| ErrorCode::InvalidMessage)?,
        );
        Ok((room, agent))
    }
}

impl GroupInviteRequestArgs {
    pub(super) fn validate(self) -> Result<(Hash32, AgentId), ErrorCode> {
        let room = parse_hash32(&self.room)?;
        let (kind, owner) = self
            .owner
            .split_once(':')
            .ok_or(ErrorCode::InvalidMessage)?;
        if kind != "agent" {
            return Err(ErrorCode::InvalidMessage);
        }
        let owner = AgentId(
            alloy_primitives::hex::decode_to_array(owner).map_err(|_| ErrorCode::InvalidMessage)?,
        );
        if owner.0 == [0; 32] {
            return Err(ErrorCode::InvalidMessage);
        }
        Ok((room, owner))
    }
}

impl GroupRejectJoinRequestArgs {
    pub(super) fn validate(self) -> Result<(Hash32, asl_types::ids::PeerId), ErrorCode> {
        Ok((parse_hash32(&self.room)?, parse_peer(&self.device)?))
    }
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentTargetArgs {
    #[schemars(regex(pattern = r"^agent:[a-fA-F0-9]{64}$"))]
    pub target: String,
}

impl AgentTargetArgs {
    pub(super) fn validate(self) -> Result<AgentId, ErrorCode> {
        let (kind, target) = self
            .target
            .split_once(':')
            .ok_or(ErrorCode::InvalidMessage)?;
        if kind != "agent" {
            return Err(ErrorCode::InvalidMessage);
        }
        alloy_primitives::hex::decode_to_array(target)
            .map(AgentId)
            .map_err(|_| ErrorCode::InvalidMessage)
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewActBudgetArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{32}$"))]
    pub conversation_id: String,
    #[schemars(range(min = 1, max = 1_000_000))]
    pub additional_messages: u32,
    #[schemars(range(min = 1, max = 720))]
    pub window_hours: u32,
}

type ParsedResourceBudget = (String, BudgetKind, u64, u64);

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewResourceBudgetArgs {
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{32}$"))]
    pub conversation_id: String,
    pub kind: String,
    #[schemars(range(min = 1))]
    pub additional: u64,
    #[schemars(range(min = 1, max = 720))]
    pub window_hours: u32,
}

impl RenewResourceBudgetArgs {
    pub(super) fn validate(self) -> Result<ParsedResourceBudget, ErrorCode> {
        if self.conversation_id.len() != 32
            || !self
                .conversation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.additional == 0
            || !(1..=720).contains(&self.window_hours)
        {
            return Err(ErrorCode::InvalidMessage);
        }
        let kind = match self.kind.as_str() {
            "message_bytes" => BudgetKind::MessageBytes,
            "model_calls" => BudgetKind::ModelCalls,
            "cpu_ms" => BudgetKind::CpuMs,
            "mailbox_bytes" => BudgetKind::MailboxBytes,
            _ => return Err(ErrorCode::InvalidMessage),
        };
        Ok((
            self.conversation_id,
            kind,
            self.additional,
            u64::from(self.window_hours) * 60 * 60 * 1_000,
        ))
    }
}

impl RenewActBudgetArgs {
    pub(super) fn validate(self) -> Result<(String, u32, u64), ErrorCode> {
        if self.conversation_id.len() != 32
            || !self
                .conversation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !(1..=1_000_000).contains(&self.additional_messages)
            || !(1..=720).contains(&self.window_hours)
        {
            return Err(ErrorCode::InvalidMessage);
        }
        Ok((
            self.conversation_id,
            self.additional_messages,
            u64::from(self.window_hours) * 60 * 60 * 1_000,
        ))
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextRequestArgs {
    #[schemars(regex(pattern = r"^(agent|group):[a-fA-F0-9]{64}$"))]
    pub target: String,
    #[schemars(length(equal = 64))]
    pub authority: String,
    pub namespace: u32,
    #[schemars(range(min = 1))]
    pub revision: u16,
    #[schemars(length(equal = 64))]
    pub digest: String,
}

impl ContextRequestArgs {
    pub(super) fn validate(self) -> Result<(String, SemanticContextRef), ErrorCode> {
        let (kind, id) = self
            .target
            .split_once(':')
            .ok_or(ErrorCode::InvalidMessage)?;
        if !matches!(kind, "agent" | "group")
            || id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ErrorCode::InvalidMessage);
        }
        let reference = SemanticContextRef {
            authority: AgentId(
                alloy_primitives::hex::decode_to_array(&self.authority)
                    .map_err(|_| ErrorCode::InvalidMessage)?,
            ),
            namespace: self.namespace,
            revision: self.revision,
            digest: Hash32(
                alloy_primitives::hex::decode_to_array(&self.digest)
                    .map_err(|_| ErrorCode::InvalidMessage)?,
            ),
        };
        let probe = WireFrame::ContextRequest(asl_types::protocol::ContextRequest {
            message_id: Id128([1; 16]),
            reference,
            expires_at_ms: 1,
        });
        encode_control(&probe).map_err(|_| ErrorCode::InvalidMessage)?;
        Ok((self.target, reference))
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmContextArgs {
    #[schemars(length(equal = 32))]
    pub request_id: String,
    #[schemars(regex(pattern = r"^[a-fA-F0-9]{64}$"))]
    pub room: Option<String>,
    #[schemars(regex(pattern = r"^agent:[a-fA-F0-9]{64}$"))]
    pub sender: Option<String>,
}

impl ConfirmContextArgs {
    pub(super) fn validate(self) -> Result<(Id128, Option<(Hash32, AgentId)>), ErrorCode> {
        let request_id = parse_id(&self.request_id)?;
        let group = match (self.room, self.sender) {
            (None, None) => None,
            (Some(room), Some(sender)) => {
                let room = parse_hash32(&room)?;
                if room.0 == [0; 32] {
                    return Err(ErrorCode::InvalidMessage);
                }
                let (kind, id) = sender.split_once(':').ok_or(ErrorCode::InvalidMessage)?;
                if kind != "agent" || id.len() != 64 {
                    return Err(ErrorCode::InvalidMessage);
                }
                let agent = AgentId(
                    alloy_primitives::hex::decode_to_array(id)
                        .map_err(|_| ErrorCode::InvalidMessage)?,
                );
                if agent.0 == [0; 32] {
                    return Err(ErrorCode::InvalidMessage);
                }
                Some((room, agent))
            }
            _ => return Err(ErrorCode::InvalidMessage),
        };
        Ok((request_id, group))
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiveOfferArgs {
    #[schemars(length(equal = 32))]
    pub offer_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct QueryArgs {
    pub query: QuerySpec,
    #[schemars(length(min = 1, max = 12))]
    pub terms: Vec<(u16, u32)>,
    pub audience: QueryAudience,
    #[schemars(range(min = 1, max = 10000))]
    pub deadline_ms: u64,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct QuerySpec {
    pub intent: QueryIntent,
    pub result_shape: QueryShape,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum QueryAudience {
    ContactsOnly,
    Public,
}

impl From<QueryAudience> for QueryScope {
    fn from(value: QueryAudience) -> Self {
        match value {
            QueryAudience::ContactsOnly => Self::ContactsOnly,
            QueryAudience::Public => Self::Public,
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum QueryIntent {
    FindEvidence,
    LocateResource,
    VerifyClaim,
    IdentifyAgent,
}

impl From<QueryIntent> for Intent {
    fn from(value: QueryIntent) -> Self {
        match value {
            QueryIntent::FindEvidence => Self::FindEvidence,
            QueryIntent::LocateResource => Self::LocateResource,
            QueryIntent::VerifyClaim => Self::VerifyClaim,
            QueryIntent::IdentifyAgent => Self::IdentifyAgent,
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum QueryShape {
    Claims,
    Resources,
    Agents,
}

impl From<QueryShape> for ResultShape {
    fn from(value: QueryShape) -> Self {
        match value {
            QueryShape::Claims => Self::Claims,
            QueryShape::Resources => Self::Resources,
            QueryShape::Agents => Self::Agents,
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct TaskArgs {
    #[schemars(length(equal = 32))]
    pub task_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FetchArgs {
    #[schemars(length(equal = 32))]
    pub task_id: String,
    #[schemars(length(equal = 32))]
    pub offer_id: String,
    /// Other offers of the same file in this task, each from a different device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = MAX_ADDITIONAL_OFFERS), inner(length(equal = 32)))]
    pub additional_offer_ids: Vec<String>,
}

const MAX_ADDITIONAL_OFFERS: usize = MAX_ACTIVE_SOURCES - 1;

impl FetchArgs {
    pub fn offer_ids(&self) -> Result<Vec<Id128>, ErrorCode> {
        if self.additional_offer_ids.len() > MAX_ADDITIONAL_OFFERS {
            return Err(ErrorCode::InvalidMessage);
        }
        let mut ids = Vec::with_capacity(1 + self.additional_offer_ids.len());
        for value in std::iter::once(&self.offer_id).chain(&self.additional_offer_ids) {
            let id = parse_id(value)?;
            if ids.contains(&id) {
                return Err(ErrorCode::InvalidMessage);
            }
            ids.push(id);
        }
        Ok(ids)
    }
}

pub(super) fn parse_id(value: &str) -> Result<Id128, ErrorCode> {
    if value.len() != Id128::LENGTH * 2 {
        return Err(ErrorCode::InvalidMessage);
    }
    let mut bytes = [0; Id128::LENGTH];
    alloy_primitives::hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| ErrorCode::InvalidMessage)?;
    Ok(Id128(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn contextual_expression_requires_exact_references_for_external_scopes() {
        let authority = "21".repeat(32);
        let digest = "31".repeat(32);
        let args = ContextExpressionArgs {
            target: format!("agent:{authority}"),
            root: None,
            expression: vec![json!("meaning"), json!(["concept", authority, 4, 1, 7])],
            required_contexts: vec![ContextRefArgs {
                authority: authority.clone(),
                namespace: 4,
                revision: 1,
                digest,
            }],
        };
        assert!(args.validate().is_ok());

        let group = ContextExpressionArgs {
            target: format!("group:{}", "41".repeat(32)),
            root: None,
            expression: vec![json!("meaning"), json!(["concept", authority, 4, 1, 7])],
            required_contexts: vec![ContextRefArgs {
                authority: authority.clone(),
                namespace: 4,
                revision: 1,
                digest: "31".repeat(32),
            }],
        };
        assert!(group.validate().is_ok());

        let incomplete = ContextExpressionArgs {
            target: format!("agent:{}", "41".repeat(32)),
            root: None,
            expression: vec![json!("meaning"), json!(["concept", authority, 4, 1, 7])],
            required_contexts: Vec::new(),
        };
        assert_eq!(
            incomplete.validate().unwrap_err(),
            ErrorCode::InvalidMessage
        );
    }

    #[test]
    fn context_request_accepts_direct_agent_or_exact_group_target() {
        let authority = "21".repeat(32);
        let digest = "31".repeat(32);
        let args = ContextRequestArgs {
            target: format!("agent:{}", "41".repeat(32)),
            authority: authority.clone(),
            namespace: 4,
            revision: 1,
            digest: digest.clone(),
        };
        let (target, reference) = args.validate().unwrap();
        assert_eq!(target, format!("agent:{}", "41".repeat(32)));
        assert_eq!(reference.authority, AgentId([0x21; 32]));
        assert_eq!(reference.digest, Hash32([0x31; 32]));

        let group_target = ContextRequestArgs {
            target: format!("group:{}", "41".repeat(32)),
            authority,
            namespace: 4,
            revision: 1,
            digest,
        };
        let (target, reference) = group_target.validate().unwrap();
        assert_eq!(target, format!("group:{}", "41".repeat(32)));
        assert_eq!(reference.authority, AgentId([0x21; 32]));
    }

    #[test]
    fn group_context_confirmation_requires_room_and_sender_together() {
        let request_id = "51".repeat(16);
        let (parsed, group) = ConfirmContextArgs {
            request_id: request_id.clone(),
            room: None,
            sender: None,
        }
        .validate()
        .unwrap();
        assert_eq!(parsed, Id128([0x51; 16]));
        assert_eq!(group, None);

        let room = "61".repeat(32);
        let sender = format!("agent:{}", "71".repeat(32));
        let (parsed, group) = ConfirmContextArgs {
            request_id,
            room: Some(room),
            sender: Some(sender),
        }
        .validate()
        .unwrap();
        assert_eq!(parsed, Id128([0x51; 16]));
        assert_eq!(group, Some((Hash32([0x61; 32]), AgentId([0x71; 32]))));

        assert_eq!(
            ConfirmContextArgs {
                request_id: "51".repeat(16),
                room: Some("61".repeat(32)),
                sender: None,
            }
            .validate()
            .unwrap_err(),
            ErrorCode::InvalidMessage
        );
    }
}
