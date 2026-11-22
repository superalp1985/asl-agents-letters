use std::io;

use asl_agent::QUERY_WINDOW_MS;
use asl_types::{
    error::{AslError, ErrorCode},
    ids::Id128,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    handler::server::common::schema_for_input,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, JsonObject,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    schemars::JsonSchema,
    service::{QuitReason, RequestContext},
    transport::{async_rw::AsyncRwTransport, stdio},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{
    client::Client,
    contract::{FetchArgs, QueryArgs, Request, TaskArgs},
};

const MAX_LINE_BYTES: usize = 64 * 1024;
const QUERY: &str = "asl_query";
const TASK_STATUS: &str = "asl_task_status";
const FETCH: &str = "asl_fetch";
const RESULT: &str = "asl_result";

pub(super) async fn run(client: Client) -> Result<(), AslError> {
    let (input, output) = stdio();
    run_stream(client, input, output).await
}

pub(super) async fn run_stream(
    client: Client,
    input: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    output: impl tokio::io::AsyncWrite + Send + Unpin + 'static,
) -> Result<(), AslError> {
    let server = ToolServer {
        client,
        tools: tool_definitions().map_err(|_| AslError::InvalidPolicyState)?,
    };
    let transport =
        AsyncRwTransport::new_server(input, output).with_max_line_length(MAX_LINE_BYTES);
    let service = server
        .serve(transport)
        .await
        .map_err(|_| io::Error::other("MCP initialization failed"))?;
    match service.waiting().await {
        Ok(QuitReason::Closed | QuitReason::Cancelled) => Ok(()),
        _ => Err(io::Error::other("MCP service stopped unexpectedly").into()),
    }
}

struct ToolServer {
    client: Client,
    tools: Vec<Tool>,
}

impl ServerHandler for ToolServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("asl", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let request = parse_request(params)?;
        // Client::call admits one IPC call at a time and returns Busy without queuing.
        let result = tokio::select! {
            biased;
            () = context.ct.cancelled() => Err(ErrorCode::Cancelled),
            result = self.client.call(request) => result,
        };
        Ok(match result {
            Ok(value) => CallToolResult::structured(value),
            Err(code) => tool_error(code),
        }
        .into())
    }
}

fn tool_definitions() -> Result<Vec<Tool>, String> {
    fn tool<T: JsonSchema + 'static>(
        name: &'static str,
        description: &'static str,
    ) -> Result<Tool, String> {
        Ok(Tool::new(name, description, schema_for_input::<T>()?))
    }

    Ok(vec![
        tool::<QueryArgs>(QUERY, "Start an authorized ASL query.")?,
        tool::<TaskArgs>(
            TASK_STATUS,
            "Get the status of an ASL task in this session.",
        )?,
        tool::<FetchArgs>(
            FETCH,
            "Download an offered file. To use multiple devices, include additional offers of the same content from this task.",
        )?,
        tool::<TaskArgs>(
            RESULT,
            "Get the final result of an ASL task in this session.",
        )?,
    ])
}

fn parse_request(params: CallToolRequestParams) -> Result<Request, ErrorData> {
    if params.input_responses.is_some() || params.request_state.is_some() {
        return Err(invalid_arguments());
    }
    let arguments = params.arguments.unwrap_or_default();
    match params.name.as_ref() {
        QUERY => {
            if !arguments.get("query").is_some_and(Value::is_object) {
                return Err(invalid_arguments());
            }
            let args: QueryArgs = parse_arguments(arguments)?;
            // Schema annotations describe these bounds but Serde does not enforce them.
            if !(1..=12).contains(&args.terms.len())
                || !(1..=QUERY_WINDOW_MS).contains(&args.deadline_ms)
            {
                return Err(invalid_arguments());
            }
            Ok(Request::Query(args))
        }
        TASK_STATUS | RESULT => {
            let args: TaskArgs = parse_arguments(arguments)?;
            if !valid_id(&args.task_id) {
                return Err(invalid_arguments());
            }
            Ok(if params.name == TASK_STATUS {
                Request::TaskStatus(args)
            } else {
                Request::Result(args)
            })
        }
        FETCH => {
            let args: FetchArgs = parse_arguments(arguments)?;
            if !valid_id(&args.task_id) || args.offer_ids().is_err() {
                return Err(invalid_arguments());
            }
            Ok(Request::Fetch(args))
        }
        _ => Err(ErrorData::invalid_params("Unknown ASL tool", None)),
    }
}

fn parse_arguments<T: DeserializeOwned>(arguments: JsonObject) -> Result<T, ErrorData> {
    serde_json::from_value(Value::Object(arguments)).map_err(|_| invalid_arguments())
}

fn valid_id(value: &str) -> bool {
    value.len() == Id128::LENGTH * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid_arguments() -> ErrorData {
    ErrorData::invalid_params("Invalid ASL tool arguments", None)
}

fn tool_error(code: ErrorCode) -> CallToolResult {
    CallToolResult::structured_error(json!({ "error_code": code }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ErrorCode as McpErrorCode, object};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn lists_only_the_four_asl_tools() {
        let tools = tool_definitions().unwrap();
        let names: Vec<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(names, [QUERY, TASK_STATUS, FETCH, RESULT]);
    }

    #[test]
    fn rejects_unknown_tools_and_invalid_arguments() {
        for params in [
            CallToolRequestParams::new("fetch_url"),
            CallToolRequestParams::new(TASK_STATUS),
            CallToolRequestParams::new(RESULT).with_arguments(object(json!({ "task_id": "bad" }))),
            CallToolRequestParams::new(FETCH).with_arguments(object(json!({
                "task_id": ID, "offer_id": ID, "path": "unexpected"
            }))),
            CallToolRequestParams::new(QUERY).with_arguments(object(json!({
                "query": { "intent": "find_evidence", "result_shape": "claims" },
                "terms": [[1, 2]], "audience": "public", "deadline_ms": 10001
            }))),
        ] {
            let Err(error) = parse_request(params) else {
                panic!("invalid tool request was accepted");
            };
            assert_eq!(error.code, McpErrorCode::INVALID_PARAMS);
        }
    }

    #[test]
    fn fetch_accepts_at_most_four_distinct_local_offer_handles() {
        let args = |extra: Value| {
            CallToolRequestParams::new(FETCH).with_arguments(object(json!({
                "task_id": ID, "offer_id": ID, "additional_offer_ids": extra
            })))
        };
        let ids = (1..=4).map(|n| format!("{n:032x}")).collect::<Vec<_>>();
        assert!(parse_request(args(json!(ids[..3]))).is_ok());
        for bad in [
            json!(ids),
            json!([ID.to_uppercase()]),
            json!(["invalid"]),
            json!([ids[0], ids[0]]),
        ] {
            assert!(parse_request(args(bad)).is_err());
        }
    }

    #[test]
    fn routes_each_tool_to_its_typed_request() {
        let query = CallToolRequestParams::new(QUERY).with_arguments(object(json!({
            "query": { "intent": "find_evidence", "result_shape": "claims" },
            "terms": [[1, 2]], "audience": "contacts_only", "deadline_ms": 10000
        })));
        let status = CallToolRequestParams::new(TASK_STATUS)
            .with_arguments(object(json!({ "task_id": ID })));
        let fetch = CallToolRequestParams::new(FETCH)
            .with_arguments(object(json!({ "task_id": ID, "offer_id": ID })));
        let result =
            CallToolRequestParams::new(RESULT).with_arguments(object(json!({ "task_id": ID })));
        assert!(matches!(parse_request(query), Ok(Request::Query(_))));
        assert!(matches!(parse_request(status), Ok(Request::TaskStatus(_))));
        assert!(matches!(parse_request(fetch), Ok(Request::Fetch(_))));
        assert!(matches!(parse_request(result), Ok(Request::Result(_))));
    }

    #[test]
    fn preserves_policy_error_code_as_structured_content() {
        let result = tool_error(ErrorCode::PolicyDenied);
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.structured_content,
            Some(json!({ "error_code": "policy_denied" }))
        );
    }
}
