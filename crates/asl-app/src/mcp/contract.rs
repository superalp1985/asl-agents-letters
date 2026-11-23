use asl_agent::QueryScope;
use asl_transfer::scheduler::MAX_ACTIVE_SOURCES;
use asl_types::{
    error::ErrorCode,
    ids::Id128,
    protocol::{Expression, Intent, ResultShape},
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
    SendExpression(ExpressionArgs),
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
