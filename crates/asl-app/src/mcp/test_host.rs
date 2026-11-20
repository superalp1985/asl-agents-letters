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
    _worker: McpWorker,
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
                scope: QueryScope::ContactsOnly,
                inbox: Some(inbox),
            },
            queries,
            downloads,
        )
        .unwrap();
        let (host, server) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(server);
        let service = tokio::spawn(stdio::run_stream(
            Client::new(home, Some(key)),
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

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).await.unwrap(), 0);
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], id, "{reply}");
        reply
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
