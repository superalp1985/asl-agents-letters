use asl_agent::QueryScope;
use asl_transfer::scheduler::MAX_ACTIVE_SOURCES;
use asl_types::{
    error::ErrorCode,
    ids::Id128,
    protocol::{Intent, ResultShape},
};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Query(QueryArgs),
    TaskStatus(TaskArgs),
    Fetch(FetchArgs),
    Result(TaskArgs),
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
