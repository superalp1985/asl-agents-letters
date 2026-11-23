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
        ListResourcesResult, ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents,
        ResourceUpdatedNotificationParam, ServerCapabilities, ServerConfig, SubscribeRequestParams,
        Tool, UnsubscribeRequestParams,
    },
    schemars::JsonSchema,
    service::{QuitReason, RequestContext},
    transport::{async_rw::AsyncRwTransport, stdio},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{
    client::Client,
    contract::{
        ExpressionArgs, FetchArgs, QueryArgs, ReceiveOfferArgs, RecoveryDownloadArgs,
        RecoveryDownloadDecisionArgs, RecoveryEventsArgs, RecoveryQueryArgs, Request, TaskArgs,
    },
};

const MAX_LINE_BYTES: usize = 64 * 1024;
const QUERY: &str = "asl_query";
const TASK_STATUS: &str = "asl_task_status";
const FETCH: &str = "asl_fetch";
const RESULT: &str = "asl_result";
const SEND: &str = "asl_send_expression";
const RECEIVE: &str = "asl_receive_offer";
const RECOVERY_TASK: &str = "asl_recovery_task";
const RECOVERY_EVENTS: &str = "asl_recovery_events";
const RECOVERY_QUERY: &str = "asl_recovery_query";
const RECOVERY_RESULT: &str = "asl_recovery_result";
const RECOVERY_DOWNLOAD: &str = "asl_recovery_download";
const RECOVERY_DOWNLOAD_DECISION: &str = "asl_recovery_download_decision";
pub(super) const AGENT_EVENTS_URI: &str = "asl://agent/inbound-events";
const GRAMMAR_URI: &str = "asl://protocol/expression-v1";

pub(super) async fn run(client: Client) -> Result<(), AslError> {
    let (input, output) = stdio();
    run_stream(client, input, output).await
}

pub(super) async fn run_stream(
    client: Client,
    input: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    output: impl tokio::io::AsyncWrite + Send + Unpin + 'static,
) -> Result<(), AslError> {
    let mut events = client.events();
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
    let peer = service.peer().clone();
    let notify = async move {
        while events.changed().await.is_ok() {
            let changed = events.borrow_and_update().has_updates();
            if changed
                && peer
                    .notify_resource_updated(ResourceUpdatedNotificationParam::new(
                        AGENT_EVENTS_URI,
                    ))
                    .await
                    .is_err()
            {
                break;
            }
        }
        // Let the SDK finish closing its transport and report why it stopped.
        std::future::pending::<()>().await;
    };
    let result = tokio::select! {
        result = service.waiting() => result,
        () = notify => unreachable!(),
    };
    match result {
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
        let capabilities = ServerCapabilities::builder().enable_tools();
        let capabilities = if self.client.has_key() {
            capabilities
                .enable_resources()
                .enable_resources_subscribe()
                .build()
        } else {
            capabilities.build()
        };
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("asl", env!("CARGO_PKG_VERSION")))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let mut resources = Vec::new();
        if self.client.has_key() {
            resources.push(
                Resource::new(GRAMMAR_URI, "asl_expression_grammar")
                    .with_mime_type("text/markdown"),
            );
        }
        if self
            .client
            .call(Request::LocalCapabilities)
            .await
            .is_ok_and(|v| v.is_object())
            && self.client.call(Request::AgentEventsAvailable).await == Ok(Value::Bool(true))
        {
            resources.push(
                Resource::new(AGENT_EVENTS_URI, "asl_inbound_events")
                    .with_mime_type("application/json"),
            );
        }
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri == GRAMMAR_URI && self.client.has_key() {
            return Ok(ReadResourceResult::new(vec![
                ResourceContents::text(
                    include_str!("../../../../docs/expression-language.md"),
                    GRAMMAR_URI,
                )
                .with_mime_type("text/markdown"),
            ])
            .into());
        }
        check_resource(&request.uri)?;
        self.require_event_protocol().await?;
        if self
            .agent_call(Request::AgentEventsAvailable, context)
            .await?
            != Value::Bool(true)
        {
            return Err(resource_error(ErrorCode::PolicyDenied));
        }
        let text = self.client.events().borrow().snapshot().to_string();
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(text, AGENT_EVENTS_URI).with_mime_type("application/json"),
        ])
        .into())
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        check_resource(&request.uri)?;
        self.require_event_protocol().await?;
        self.agent_call(Request::SubscribeAgentEvents, context)
            .await?;
        Ok(())
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        check_resource(&request.uri)?;
        self.require_event_protocol().await?;
        self.agent_call(Request::UnsubscribeAgentEvents, context)
            .await?;
        Ok(())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools = self.tools.clone();
        if self.client.is_recovery() {
            tools.retain(|tool| tool.name != FETCH);
        }
        if self.client.has_key()
            && let Ok(caps) = self.client.call(Request::LocalCapabilities).await
        {
            if caps["send_expression"] == true {
                tools.push(Tool::new(SEND, "Queue a symbolic ASL letter for an admitted agent or group. See asl://protocol/expression-v1 for syntax. This is not delivery confirmation.", schema_for_input::<ExpressionArgs>().map_err(|_| invalid_arguments())?));
            }
            if caps["receive_offer"] == true {
                tools.push(Tool::new(
                    RECEIVE,
                    "Select a notified incoming offer. Local inbox and approval rules still apply.",
                    schema_for_input::<ReceiveOfferArgs>().map_err(|_| invalid_arguments())?,
                ));
            }
            if caps["task_recovery"] == true {
                tools.push(Tool::new(
                    RECOVERY_TASK,
                    "Read the last recorded status of your own recoverable query. Does not rerun or fetch anything.",
                    schema_for_input::<TaskArgs>().map_err(|_| invalid_arguments())?,
                ));
                tools.push(Tool::new(
                    RECOVERY_EVENTS,
                    "Read recorded query status changes after a cursor. Start with 0 and continue with next_cursor.",
                    schema_for_input::<RecoveryEventsArgs>().map_err(|_| invalid_arguments())?,
                ));
            }
            if caps["recovery_query"] == true {
                tools.push(Tool::new(
                    RECOVERY_QUERY,
                    "Submit a recoverable query once. Before sending, save a fresh 32-hex request ID, the complete request, and its UNIX millisecond retry deadline. Retry with identical arguments; a returned task ID is not confirmation of delivery.",
                    schema_for_input::<RecoveryQueryArgs>().map_err(|_| invalid_arguments())?,
                ));
            }
            if caps["recovery_results"] == true {
                tools.push(Tool::new(
                    RECOVERY_RESULT,
                    "Read a retained structured result from your own recoverable query. Results are stored only with the separate explicit result-retention setting.",
                    schema_for_input::<TaskArgs>().map_err(|_| invalid_arguments())?,
                ));
            }
            if caps["recovery_download"] == true {
                tools.push(Tool::new(
                    RECOVERY_DOWNLOAD,
                    "Read status with resume=false or queue resumption with resume=true. Requires local approval for this existing transfer. A group transfer must still match its original membership version. Does not select files or sources.",
                    schema_for_input::<RecoveryDownloadArgs>().map_err(|_| invalid_arguments())?,
                ));
            }
            if caps["recovery_download_decision"] == true {
                tools.push(Tool::new(
                    RECOVERY_DOWNLOAD_DECISION,
                    "Read the state of a download decision shared by the local operator. Cannot approve, deny, or start a download.",
                    schema_for_input::<RecoveryDownloadDecisionArgs>().map_err(|_| invalid_arguments())?,
                ));
            }
        }
        Ok(ListToolsResult::with_all_items(tools))
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

impl ToolServer {
    async fn require_event_protocol(&self) -> Result<(), ErrorData> {
        if self
            .client
            .call(Request::LocalCapabilities)
            .await
            .map_err(resource_error)?
            .is_object()
        {
            Ok(())
        } else {
            Err(resource_error(ErrorCode::IncompatibleVersion))
        }
    }

    async fn agent_call(
        &self,
        request: Request,
        context: RequestContext<RoleServer>,
    ) -> Result<Value, ErrorData> {
        tokio::select! {
            biased;
            () = context.ct.cancelled() => Err(resource_error(ErrorCode::Cancelled)),
            result = self.client.call(request) => result.map_err(resource_error),
        }
    }
}

fn check_resource(uri: &str) -> Result<(), ErrorData> {
    if uri != AGENT_EVENTS_URI {
        return Err(ErrorData::resource_not_found("Unknown ASL resource", None));
    }
    Ok(())
}

fn resource_error(code: ErrorCode) -> ErrorData {
    ErrorData::resource_not_found(
        "ASL event resource unavailable",
        Some(json!({ "error_code": code })),
    )
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
        SEND => Ok(Request::SendExpression(parse_arguments(arguments)?)),
        RECEIVE => Ok(Request::ReceiveOffer(parse_arguments(arguments)?)),
        RECOVERY_EVENTS => Ok(Request::RecoveryEvents(parse_arguments(arguments)?)),
        RECOVERY_DOWNLOAD => {
            let args: RecoveryDownloadArgs = parse_arguments(arguments)?;
            if !valid_id(&args.transfer_id) {
                return Err(invalid_arguments());
            }
            Ok(Request::RecoveryDownload(args))
        }
        RECOVERY_DOWNLOAD_DECISION => {
            let args: RecoveryDownloadDecisionArgs = parse_arguments(arguments)?;
            if !valid_id(&args.approval_id) {
                return Err(invalid_arguments());
            }
            Ok(Request::RecoveryDownloadDecision(args))
        }
        RECOVERY_QUERY => {
            let args: RecoveryQueryArgs = parse_arguments(arguments)?;
            if !valid_id(&args.request_id) || args.valid_until_ms <= 0 {
                return Err(invalid_arguments());
            }
            validate_query(&args.request)?;
            Ok(Request::RecoveryQuery(args))
        }
        QUERY => {
            if !arguments.get("query").is_some_and(Value::is_object) {
                return Err(invalid_arguments());
            }
            let args: QueryArgs = parse_arguments(arguments)?;
            validate_query(&args)?;
            Ok(Request::Query(args))
        }
        TASK_STATUS | RESULT | RECOVERY_TASK | RECOVERY_RESULT => {
            let args: TaskArgs = parse_arguments(arguments)?;
            if !valid_id(&args.task_id) {
                return Err(invalid_arguments());
            }
            Ok(match params.name.as_ref() {
                TASK_STATUS => Request::TaskStatus(args),
                RECOVERY_TASK => Request::RecoveryTask(args),
                RECOVERY_RESULT => Request::RecoveryResult(args),
                _ => Request::Result(args),
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

fn validate_query(args: &QueryArgs) -> Result<(), ErrorData> {
    if !(1..=12).contains(&args.terms.len()) || !(1..=QUERY_WINDOW_MS).contains(&args.deadline_ms) {
        return Err(invalid_arguments());
    }
    Ok(())
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
