#![cfg(windows)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

const KEY: &str = "ASL_MCP_KEY";
const SCOPE: &str = "ASL_MCP_SCOPE";
const INBOX: &str = "ASL_MCP_INBOX_GRANT";
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(25);

#[test]
fn mcp_stdio_lists_only_the_four_tools_and_requires_a_separate_local_grant() {
    let root = TestRoot::new();
    let home = root.0.join("unused");
    let mut host = Host::start(&home, None);
    let listed = host.request("tools/list", json!({}));
    let mut names: Vec<_> = listed["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["asl_fetch", "asl_query", "asl_result", "asl_task_status"]
    );
    let reply = host.call("fetch_url", json!({"url":"https://example.invalid"}));
    assert_rejected(&reply);
    let reply = host.call("asl_query", query("contacts_only"));
    assert_error(&reply, "policy_denied");
    assert!(!home.exists(), "stdio must not initialize an ASL home");
}

#[test]
fn inbox_grant_is_managed_by_local_cli_and_revocable() {
    let root = TestRoot::new();
    let home = root.0.join("home");
    let inbox = root.0.join("用户收件目录");
    fs::create_dir(&inbox).unwrap();
    let cli = || {
        let mut command = command(env!("CARGO_BIN_EXE_asl-core"));
        command.env("ASL_HOME", &home).arg("--downloads");
        command
    };
    let output = cli()
        .arg("authorize-inbox")
        .arg(&inbox)
        .arg("1048576")
        .output()
        .unwrap();
    assert!(output.status.success());
    let grant: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = grant["inbox_grant_id"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    let output = cli().args(["revoke-inbox", id]).output().unwrap();
    assert!(output.status.success());
    let revoked: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(revoked["inbox_grant_id"], id);
}

#[test]
fn authenticated_stdio_routes_to_real_core_and_new_attachment_cannot_read_previous_task() {
    let root = TestRoot::new();
    let home = root.0.join("core");
    let key: [u8; 32] = rand::random();
    let key = alloy_primitives::hex::encode(key);
    let bin = root.0.join("bin");
    fs::create_dir(&bin).unwrap();
    // Cargo publishes hard-linked binaries. The sandbox checks that installed
    // helpers have one link before changing their executable ACL.
    for (source, name) in [
        (env!("CARGO_BIN_EXE_asl-core"), "asl-core.exe"),
        (env!("CARGO_BIN_EXE_asl-net"), "asl-net.exe"),
        (env!("CARGO_BIN_EXE_asl-worker"), "asl-worker.exe"),
        (env!("CARGO_BIN_EXE_asl-extractor"), "asl-extractor.exe"),
    ] {
        fs::copy(source, bin.join(name)).unwrap();
    }
    let mut core = Process(
        Command::new(bin.join("asl-core.exe"))
            .env("ASL_HOME", &home)
            .env(KEY, &key)
            .env(SCOPE, "contacts_only")
            .env_remove(INBOX)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut host = Host::start(&home, Some(&key));
    let deadline = Instant::now() + Duration::from_secs(10);
    let task = loop {
        let reply = host.call("asl_query", query("contacts_only"));
        if let Some(id) = payload(&reply)["task_id"].as_str() {
            break id.to_owned();
        }
        assert!(Instant::now() < deadline, "Core did not accept: {reply}");
        assert!(core.0.try_wait().unwrap().is_none(), "Core exited");
        assert_error(&reply, "offline");
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(task.len(), 32);
    assert_error(&host.call("asl_query", query("public")), "policy_denied");

    let reply = host.call("asl_task_status", json!({"task_id":task}));
    assert!(reply.get("error").is_none(), "{reply}");
    assert_ne!(reply["result"]["isError"], true, "{reply}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let reply = host.call("asl_result", json!({"task_id":task}));
        if payload(&reply)["status"] == "failed" {
            assert_eq!(payload(&reply)["error"], "offline");
            break;
        }
        assert!(Instant::now() < deadline, "{reply}");
        assert_error(&reply, "busy");
        thread::sleep(Duration::from_millis(50));
    }
    assert_rejected(&host.call(
        "asl_fetch",
        json!({"task_id":task,"offer_id":"00".repeat(16),"path":"unapproved.bin"}),
    ));
    host.close();

    let mut second = Host::start(&home, Some(&key));
    assert_error(
        &second.call("asl_task_status", json!({"task_id":task})),
        "not_found",
    );
    second.close();

    let wrong_key = alloy_primitives::hex::encode(rand::random::<[u8; 32]>());
    let mut wrong = Host::start(&home, Some(&wrong_key));
    assert_error(
        &wrong.call("asl_query", query("contacts_only")),
        "policy_denied",
    );
}

fn query(audience: &str) -> Value {
    json!({
        "query": {"intent":"locate_resource","result_shape":"resources"},
        "terms": [[1,101]],
        "audience": audience,
        "deadline_ms": 5000
    })
}

fn payload(reply: &Value) -> &Value {
    &reply["result"]["structuredContent"]
}

fn assert_rejected(reply: &Value) {
    assert!(
        reply.get("error").is_some() || reply["result"]["isError"] == true,
        "{reply}"
    );
}

fn assert_error(reply: &Value, expected: &str) {
    assert_rejected(reply);
    assert!(reply.to_string().contains(expected), "{reply}");
}

fn command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command.env_remove(KEY).env_remove(SCOPE).env_remove(INBOX);
    command
}

struct Host {
    process: Process,
    input: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
}

impl Host {
    fn start(home: &Path, key: Option<&str>) -> Self {
        let mut command = command(env!("CARGO_BIN_EXE_asl"));
        if let Some(key) = key {
            command.env(KEY, key);
        }
        let mut process = Process(
            command
                .args(["mcp", "--home"])
                .arg(home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let output = process.0.stdout.take().unwrap();
        let (send, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(output).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let input = process.0.stdin.take();
        let mut host = Self {
            process,
            input,
            lines,
            next_id: 1,
        };
        let version = rmcp::model::ProtocolVersion::LATEST_WITH_INITIALIZE.as_str();
        let reply = host.request(
            "initialize",
            json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name":"asl-contract-test","version":"1"}
            }),
        );
        assert_eq!(reply["result"]["protocolVersion"], version, "{reply}");
        host.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        host
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let line = self.lines.recv_timeout(PROTOCOL_TIMEOUT).unwrap();
        let message: Value = serde_json::from_str(&line).expect("stdout is MCP JSON only");
        assert_eq!(message["id"], id, "{message}");
        assert_eq!(message["jsonrpc"], "2.0", "{message}");
        message
    }

    fn send(&mut self, message: Value) {
        let stream = self.input.as_mut().unwrap();
        writeln!(stream, "{message}").unwrap();
        stream.flush().unwrap();
    }

    fn close(mut self) {
        drop(self.input.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.process.0.try_wait().unwrap() {
                assert!(status.success(), "{status}");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "stdio process did not exit on EOF"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("asl-mcp-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let root = self.0.canonicalize().unwrap();
        let base = std::env::temp_dir().canonicalize().unwrap();
        assert_eq!(root.parent(), Some(base.as_path()));
        assert_eq!(root.file_name(), self.0.file_name());
        fs::remove_dir_all(root).unwrap();
    }
}
