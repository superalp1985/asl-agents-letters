use std::path::PathBuf;

use asl_agent::QueryScope;
use asl_types::ids::Id128;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf},
    task::JoinHandle,
};

use crate::{OutgoingQueryPort, downloads::DownloadPort};

use super::{HostGrant, McpWorker, client::Client, grant::Key, stdio};

pub(crate) struct Host {
    _worker: Option<McpWorker>,
    service: JoinHandle<Result<(), asl_types::error::AslError>>,
    input: WriteHalf<DuplexStream>,
    output: BufReader<ReadHalf<DuplexStream>>,
    next_id: u64,
}

impl Host {
    pub(crate) async fn connect(
        home: PathBuf,
        inbox: Id128,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
    ) -> Self {
        let key = Key::new(rand::random());
        let worker = McpWorker::spawn(
            home.clone(),
            HostGrant {
                key: key.clone(),
                recovery_key: None,
                recovery_results: false,
                scope: QueryScope::ContactsOnly,
                inbox: Some(inbox),
                expressions: false,
                agent_push: true,
            },
            queries,
            downloads,
        )
        .unwrap();
        let mut host = Self::attach(home, key, Some(worker)).await;
        host.subscribe().await;
        host
    }

    pub(crate) async fn connect_to_core(home: PathBuf, key: [u8; 32]) -> Self {
        let mut host = Self::attach(home, Key::new(key), None).await;
        host.subscribe().await;
        host
    }

    async fn subscribe(&mut self) {
        assert!(
            self.request(
                "resources/subscribe",
                json!({"uri":stdio::AGENT_EVENTS_URI})
            )
            .await
            .get("result")
            .is_some()
        );
    }

    async fn attach(home: PathBuf, key: Key, worker: Option<McpWorker>) -> Self {
        let (host, server) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(server);
        let service = tokio::spawn(stdio::run_stream(
            Client::new(home, Some(key), false),
            reader,
            writer,
        ));
        let (output, input) = tokio::io::split(host);
        let mut host = Self {
            _worker: worker,
            service,
            input,
            output: BufReader::new(output),
            next_id: 1,
        };
        let version = rmcp::model::ProtocolVersion::LATEST_WITH_INITIALIZE.as_str();
        let init = host
            .request(
                "initialize",
                json!({
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name":"asl-loopback-test","version":"1"}
                }),
            )
            .await;
        assert_eq!(init["result"]["protocolVersion"], version, "{init}");
        host.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        host
    }

    pub(crate) async fn call(&mut self, name: &str, arguments: Value) -> Value {
        let reply = self
            .request("tools/call", json!({"name":name,"arguments":arguments}))
            .await;
        assert!(reply.get("error").is_none(), "{reply}");
        reply["result"]["structuredContent"].clone()
    }

    pub(crate) async fn notified(&mut self, kind: &str, field: &str, id: &Value) -> Value {
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).await.unwrap(), 0);
        let notice: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(notice["method"], "notifications/resources/updated");
        assert_eq!(notice["params"]["uri"], stdio::AGENT_EVENTS_URI);
        let read = self
            .request("resources/read", json!({"uri":stdio::AGENT_EVENTS_URI}))
            .await;
        let snapshot: Value =
            serde_json::from_str(read["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
        snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["event"])
            .find(|e| e["kind"] == kind && &e["details"][field] == id)
            .expect("pushed event must be readable")["details"]
            .clone()
    }

    pub(crate) async fn wait_transfer_notice(&mut self, kind: &str, transfer: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                let result = self
                    .request("resources/read", json!({"uri":stdio::AGENT_EVENTS_URI}))
                    .await;
                let snapshot: Value =
                    serde_json::from_str(result["result"]["contents"][0]["text"].as_str().unwrap())
                        .unwrap();
                if snapshot["events"].as_array().unwrap().iter().any(|e| {
                    e["event"]["kind"] == kind && e["event"]["details"]["transfer_id"] == transfer
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("transfer notice was not delivered");
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        loop {
            let mut line = String::new();
            assert_ne!(self.output.read_line(&mut line).await.unwrap(), 0);
            let reply: Value = serde_json::from_str(&line).unwrap();
            if reply["method"] == "notifications/resources/updated" {
                continue;
            }
            assert_eq!(reply["id"], id, "{reply}");
            return reply;
        }
    }

    async fn send(&mut self, message: Value) {
        self.input
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
    }

    pub(crate) async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        self.service.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn tool_discovery_keeps_an_older_cores_live_attachment() {
    use super::{
        contract::{Request, ServerFrame},
        secure::SecurePipe,
    };
    use crate::{paths::AppPaths, transfer::tests::Fixture};
    use std::time::Duration;

    let temp = Fixture::new();
    let home = temp.path().join("legacy-core");
    AppPaths::open(&home).unwrap();
    let key = Key::new([43; 32]);
    let mut listener = asl_policy::LocalPipeServer::bind(&home).unwrap();
    let legacy = async {
        {
            let mut connection = listener.accept().await.unwrap();
            let mut pipe = SecurePipe::respond(connection.stream(), &key)
                .await
                .unwrap();
            assert!(matches!(
                pipe.receive::<Request>().await.unwrap(),
                Request::LocalCapabilities
            ));
        }
        let mut connection = listener.accept().await.unwrap();
        let mut pipe = SecurePipe::respond(connection.stream(), &key)
            .await
            .unwrap();
        assert!(matches!(
            pipe.receive::<Request>().await.unwrap(),
            Request::Query(_)
        ));
        pipe.send(&ServerFrame::Reply(Ok(json!({"task_id":"ab".repeat(16)}))))
            .await
            .unwrap();
        assert!(matches!(
            pipe.receive::<Request>().await.unwrap(),
            Request::TaskStatus(_)
        ));
        pipe.send(&ServerFrame::Reply(Ok(json!({"status":"complete"}))))
            .await
            .unwrap();
        assert!(pipe.receive::<Request>().await.is_err());
    };
    let host = async {
        let mut host = Host::attach(home, key.clone(), None).await;
        let query = host
            .call(
                "asl_query",
                json!({
                    "query":{"intent":"locate_resource","result_shape":"resources"},
                    "audience":"contacts_only","deadline_ms":1000,"terms":[[1,101]]
                }),
            )
            .await;
        let task = &query["task_id"];
        assert_eq!(task, &json!("ab".repeat(16)));
        let list = host.request("tools/list", json!({})).await;
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 4);
        let denied = host
            .call("asl_recovery_task", json!({"task_id":task}))
            .await;
        assert_eq!(denied["error_code"], "policy_denied");
        let status = host.call("asl_task_status", json!({"task_id":task})).await;
        assert_eq!(status["status"], "complete", "{status}");
        host.close().await;
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(legacy, host);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn idle_host_receives_structured_letter_and_requests_missing_inbox_without_fetch() {
    use crate::{
        agent_mail::{MailCommand, Mailbox},
        downloads::{DownloadSource, download_channel},
        identity::DeviceIdentity,
        outgoing_query_channel,
        paths::AppPaths,
        transfer::tests::Fixture,
    };
    use asl_types::{
        ids::{AgentId, Hash32},
        protocol::{Expression, ExpressionLetter, MediaKind, Offer, WireFrame},
    };
    use std::time::Duration;

    let temp = Fixture::new();
    let home = temp.path().join("mail");
    AppPaths::open(&home).unwrap();
    let (queries, _queries) = outgoing_query_channel();
    let (downloads, _downloads) = download_channel();
    let key = Key::new(rand::random());
    let mut mailbox = Mailbox::default();
    let grant = HostGrant {
        key: key.clone(),
        recovery_key: None,
        recovery_results: false,
        scope: QueryScope::ContactsOnly,
        inbox: None,
        expressions: true,
        agent_push: true,
    };
    let worker = McpWorker::spawn_with_mail(
        home.clone(),
        grant,
        queries,
        downloads,
        mailbox.port.clone(),
        None,
    )
    .unwrap();
    let mut host = Host::attach(home, key, Some(worker)).await;
    let uri = stdio::AGENT_EVENTS_URI;
    let listed = host.request("tools/list", json!({})).await;
    assert!(
        listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "asl_send_expression")
    );
    assert!(
        host.request("resources/subscribe", json!({"uri":uri}))
            .await
            .get("result")
            .is_some()
    );
    let source = DownloadSource {
        agent_id: AgentId([3; 32]),
        peer_id: DeviceIdentity::generate().unwrap().peer_id(),
    };
    let term = json!([
        "request",
        ["if", ["bool", true], ["int", "7"], ["int", "8"]]
    ]);
    let frame = WireFrame::Expression(ExpressionLetter {
        message_id: Id128([1; 16]),
        root_task_id: Id128([2; 16]),
        created_at_ms: 1,
        expires_at_ms: 100,
        expression: Expression::from_json(&term).unwrap(),
    });
    assert!(mailbox.observe(source.clone(), [1; 16], None, &frame, 3));
    assert!(!mailbox.observe(source.clone(), [1; 16], None, &frame, 3));
    for file in [false, true] {
        if file {
            let offer = WireFrame::Offer(Offer {
                message_id: Id128([5; 16]),
                root_task_id: Id128([2; 16]),
                content_id: Hash32([7; 32]),
                file_size: 21,
                media_kind: MediaKind::Other,
                concepts: vec![],
                expires_at_ms: 100,
            });
            assert!(mailbox.observe(source.clone(), [1; 16], None, &offer, 3));
        }
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), host.output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let notification: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(notification["method"], "notifications/resources/updated");
        assert_eq!(notification["params"]["uri"], uri);
        let read = host.request("resources/read", json!({"uri":uri})).await;
        let state: Value =
            serde_json::from_str(read["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
        let event = &state["events"].as_array().unwrap().last().unwrap()["event"];
        if file {
            assert_eq!(event["kind"], "file_offer");
            assert_eq!(event["details"]["inbox_permission_required"], true);
            let offer_id = event["details"]["offer_id"].clone();
            let request = host.call("asl_receive_offer", json!({"offer_id":offer_id}));
            let core = async {
                let Some(MailCommand::RequestInbox { handle, reply, .. }) =
                    mailbox.commands.recv().await
                else {
                    panic!("only a permission request is allowed");
                };
                assert_eq!(alloy_primitives::hex::encode(handle.0), offer_id);
                let (decision, issued) = tokio::sync::oneshot::channel();
                reply.send(Ok(issued)).unwrap();
                decision
            };
            let (result, decision) = tokio::join!(request, core);
            assert_eq!(result["status"], "inbox_permission_required");
            decision
                .send(Err(asl_types::error::AslError::PolicyDenied))
                .unwrap();
            let denied = host
                .notified("inbox_permission", "status", &json!("not_granted"))
                .await;
            assert_eq!(denied["error_code"], "policy_denied");
        } else {
            assert_eq!(event["details"]["expression"], term);
        }
    }
    host.request("resources/unsubscribe", json!({"uri":uri}))
        .await;
    assert!(!mailbox.interested());
    host.close().await;
}
