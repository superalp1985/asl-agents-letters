use asl_agent::QueryScope;
use asl_types::protocol::{Intent, ResultShape};
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
}
