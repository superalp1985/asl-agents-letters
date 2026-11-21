use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use asl_types::{
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{ConceptRef, Intent, Query, ResultShape},
    record::{DeviceDirectory, RecordPayload, device_directory_commitment},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    chain::{
        DurableIdentityResolver, DurableResolverConfigV1,
        test_support::{process_fixture_client, proof_fixtures_for_agents},
    },
    identity::{AgentIdentity, DeviceIdentity},
    ipc::{IpcMessage, run_net_pipe_fixture, write_net_startup_prelude},
    network::NetworkCommand,
    network_settings::NetworkSettingsV1,
    profile::{AdmittedNetworkEvent, fresh_id, sign_record},
    supervisor::{NetRuntime, sibling_binary_directory, unix_time_ms},
    transfer::tests::Fixture,
};

use super::{
    AppPaths, AslError, GroupApplication, LocalGroupAction, LocalGroupCommand, Supervisor,
    TransportKind,
};

const CHILD: &str = "supervisor::groups::process_tests::group_core_child";
const RESULT_PREFIX: &str = "ASL_GROUP_FIXTURE:";
const WAIT: Duration = Duration::from_secs(15);
type RegistryClaim = (AgentId, [[u8; 32]; 3]);

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
enum Verification {
    Protocol,
    AppContainer,
}

#[derive(Serialize, Deserialize)]
struct RegistryFixture {
    now_ms: u64,
    claims: [RegistryClaim; 3],
    verification: Verification,
}

#[derive(Serialize, Deserialize)]
enum Action {
    Peers,
    Create,
    Dial(SocketAddr, Vec<u8>),
    Invite(Hash32, [u8; 16]),
    List,
    Approve(Id128),
    Room(Hash32),
    Send(Hash32),
    Remove(Hash32, Vec<u8>),
}

impl Action {
    fn into_local(self, now_ms: u64) -> Result<LocalGroupAction, AslError> {
        Ok(match self {
            Self::Peers => LocalGroupAction::Peers,
            Self::Create => LocalGroupAction::Create,
            Self::Dial(address, peer) => LocalGroupAction::Dial {
                address,
                peer: PeerId::from_bytes(peer).map_err(|_| AslError::InvalidIdentity)?,
            },
            Self::Invite(room, connection_id) => LocalGroupAction::Invite {
                room,
                connection_id,
            },
            Self::List => LocalGroupAction::List,
            Self::Approve(invite) => LocalGroupAction::Approve(invite),
            Self::Room(room) => LocalGroupAction::Room(room),
            Self::Remove(room, peer) => LocalGroupAction::Remove {
                room,
                peer: PeerId::from_bytes(peer).map_err(|_| AslError::InvalidIdentity)?,
            },
            Self::Send(room) => LocalGroupAction::SendApplication {
                room,
                application: Box::new(GroupApplication::Query(Query {
                    message_id: Id128(fresh_id()?),
                    root_task_id: Id128(fresh_id()?),
                    created_at_ms: now_ms,
                    expires_at_ms: now_ms + 10_000,
                    intent_id: Intent::LocateResource,
                    topics: vec![ConceptRef::RUST],
                    constraints: Vec::new(),
                    result_shape: ResultShape::Resources,
                    budget: 1,
                })),
            },
        })
    }
}

#[test]
fn group_messages_cross_core_processes_over_framed_ipc_and_tcp() {
    verify_group_delivery(Verification::Protocol);
}

#[test]
#[ignore = "requires a working TCP loopback route between separate Net AppContainers"]
fn group_messages_cross_sandboxed_net_processes() {
    verify_group_delivery(Verification::AppContainer);
}

fn verify_group_delivery(verification: Verification) {
    let fixture = Fixture::new();
    if verification == Verification::AppContainer {
        let bin = fixture.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let source = sibling_binary_directory().unwrap();
        for executable in ["asl-net.exe", "asl-worker.exe", "asl-extractor.exe"] {
            fs::copy(source.join(executable), bin.join(executable)).unwrap();
        }
    }

    let now_ms = unix_time_ms().unwrap();
    let mut nodes = ["first", "second", "third"].map(|name| {
        let home = fixture.path().join(name);
        let (peer, claim) = init_node(&home, now_ms);
        (peer, home, claim)
    });
    // Probe order is by PeerId. Put the creator first so a new sync round
    // can obtain its commits before consulting another member's older head.
    nodes.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let registry = RegistryFixture {
        now_ms,
        claims: nodes.each_ref().map(|(_, _, claim)| *claim),
        verification,
    };
    let registry_path = fixture.path().join("registry.json");
    fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();

    let [
        (creator_peer, creator_home, _),
        (first_peer, first_home, _),
        (second_peer, second_home, _),
    ] = &nodes;
    let (mut creator, creator_ready) = CoreProcess::start(creator_home, &registry_path);
    let (mut first, first_ready) = CoreProcess::start(first_home, &registry_path);
    let (mut second, second_ready) = CoreProcess::start(second_home, &registry_path);
    first.dial(&creator_ready, creator_peer);
    first.connection(&creator_ready["peer"]);
    let first_connection = creator.connection(&first_ready["peer"]);
    let room = Hash32(parse_hex(&creator.ok(Action::Create)["room"]));
    creator.invite(room, first_connection, &mut first, 1);

    second.dial(&creator_ready, creator_peer);
    second.connection(&creator_ready["peer"]);
    let second_connection = creator.connection(&second_ready["peer"]);
    // Exchange signed directories so both members can verify the other's
    // leaf in Welcome or Add through the usual connection admission.
    second.dial(&first_ready, first_peer);
    second.connection(&first_ready["peer"]);
    first.connection(&second_ready["peer"]);
    creator.invite(room, second_connection, &mut second, 2);
    first.wait_epoch(room, 2);

    let sent = creator.ok(Action::Send(room));
    assert_eq!(sent["available"], 2);
    assert_eq!(sent["queued"], 2);
    first.receive_query(room, &sent, &creator_ready["peer"]);
    let second_received = second.receive_query(room, &sent, &creator_ready["peer"]);

    let sent = first.ok(Action::Send(room));
    assert_eq!(sent["available"], 1);
    assert_eq!(sent["queued"], 1);
    creator.receive_query(room, &sent, &first_ready["peer"]);

    assert_eq!(
        creator.ok(Action::Remove(room, second_peer.as_bytes().to_vec()))["mls_epoch"],
        3
    );
    // Check fan-out before idle timeouts can hide an incorrectly retained
    // recipient. The remaining member may not have applied Remove yet.
    assert_eq!(creator.connection(&second_ready["peer"]), second_connection);
    let sent = creator.ok(Action::Send(room));
    assert_eq!(sent["available"], 1);
    assert_eq!(sent["queued"], 1);

    first.wait_epoch(room, 3);
    let sent = creator.ok(Action::Send(room));
    assert_eq!(sent["available"], 1);
    assert_eq!(sent["queued"], 1);
    first.receive_query(room, &sent, &creator_ready["peer"]);
    assert_eq!(
        second.ok(Action::Room(room))["last_received"],
        second_received
    );
    let after = creator.ok(Action::Room(room));
    assert_eq!(after["state"], "needs_sync");

    creator.close();
    first.close();
    second.close();
}

#[test]
#[ignore = "fixture subprocess spawned by the group process test"]
fn group_core_child() {
    let Some(home) = std::env::var_os("ASL_GROUP_FIXTURE_HOME") else {
        return;
    };
    let paths = AppPaths::open(Path::new(&home)).unwrap();
    let registry: RegistryFixture = serde_json::from_slice(
        &fs::read(std::env::var_os("ASL_GROUP_FIXTURE_REGISTRY").unwrap()).unwrap(),
    )
    .unwrap();
    let (deployment, finalized, proofs) = proof_fixtures_for_agents(&registry.claims, 8);
    let now_secs = registry.now_ms / 1_000;
    let (consensus, client) = process_fixture_client(finalized, now_secs);
    let mut resolver = DurableIdentityResolver::create(
        asl_store::open_store(&paths.state().join("asl.sqlite3")).unwrap(),
        DurableResolverConfigV1 {
            consensus,
            deployment,
            max_cache_age_secs: 120,
            cache_capacity: 8,
        },
        client,
        now_secs,
    )
    .unwrap();
    for proof in &proofs {
        resolver
            .accept_proof(proof.agent_id, proof, now_secs)
            .unwrap();
    }
    let signed = fs::read(paths.signed_device_directory()).unwrap();
    let bin = Path::new(&home).parent().unwrap().join("bin");
    let launcher = asl_policy::sandbox::SandboxLauncher::new(
        bin.join("asl-net.exe"),
        bin.join("asl-worker.exe"),
        bin.join("asl-extractor.exe"),
    )
    .unwrap();
    let mut net_thread = None;
    let mut supervisor = match registry.verification {
        Verification::AppContainer => Supervisor::start_with_launcher(paths, launcher).unwrap(),
        Verification::Protocol => {
            Supervisor::start_with_net(paths, launcher, |_, device, groups| {
                let (net_input, mut core_output) = io::pipe()?;
                let (core_input, net_output) = io::pipe()?;
                write_net_startup_prelude(&mut core_output, device, groups)?;
                net_thread = Some(
                    thread::Builder::new()
                        .name("asl-net-protocol-fixture".into())
                        .spawn(move || {
                            // Closing the Core writer ends this fixture, as it does
                            // for a child when its private command stream disappears.
                            let _ = run_net_pipe_fixture(net_input, net_output);
                        })?,
                );
                NetRuntime::from_pipes(core_output, core_input, None, &device.peer_id())
            })
            .unwrap()
        }
    };
    supervisor
        .activate_network_admission(signed, resolver, unix_time_ms().unwrap())
        .unwrap();
    supervisor
        .send_startup_network_operation(|operation_id| NetworkCommand::Listen {
            operation_id,
            kind: TransportKind::Tcp,
            address: (Ipv4Addr::LOCALHOST, 0).into(),
        })
        .expect("Net must accept an ephemeral loopback listener");
    let IpcMessage::Listening {
        address,
        kind: TransportKind::Tcp,
    } = supervisor
        .net
        .receive_network_event(WAIT)
        .expect("Net must report its bound TCP endpoint")
    else {
        panic!("expected a TCP listening event");
    };
    emit(json!({"tcp": address, "peer": super::peer_text(&supervisor.device_peer_id)}));

    let (input, commands) = mpsc::sync_channel(1);
    supervisor.group_controls = Some(commands);
    let reader = thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let action: Action = serde_json::from_str(&line.unwrap()).unwrap();
            let action = action.into_local(unix_time_ms().unwrap()).unwrap();
            let (reply, response) = mpsc::sync_channel(1);
            if input.send(LocalGroupCommand { action, reply }).is_err() {
                break;
            }
            let Ok(result) = response.recv() else { break };
            emit(match result {
                Ok(value) => value,
                Err(error) => json!({"error": error.to_string()}),
            });
        }
    });
    let result = supervisor.run_loop(
        |_, event| {
            if let AdmittedNetworkEvent::OperationFailed { code, .. } = event {
                eprintln!("Group fixture Net operation failed: {code:?}");
            }
            Ok(())
        },
        |_| Ok(()),
        |core| {
            if core.group_controls.is_none() {
                return Err(AslError::NotFound);
            }
            Ok(())
        },
    );
    assert!(matches!(result, Err(AslError::NotFound)), "{result:?}");
    reader.join().unwrap();
    if let Some(net_thread) = net_thread {
        net_thread.join().unwrap();
    }
}

fn init_node(home: &Path, now_ms: u64) -> (PeerId, RegistryClaim) {
    let paths = AppPaths::open(home).unwrap();
    let root = AgentIdentity::load_or_create_protected(&paths.agent_root_key()).unwrap();
    let device = DeviceIdentity::load_or_create_protected(&paths.device_key()).unwrap();
    let peer = device.peer_id();
    let directory = DeviceDirectory {
        agent_id: root.agent_id(),
        registry_sequence: 1,
        devices: vec![
            root.issue_device_certificate(peer.clone(), 1, now_ms, now_ms + 120_000)
                .unwrap(),
        ],
        revoked_serials: Vec::new(),
    };
    let mut values = [[0; 32]; 3];
    values[0][12..].copy_from_slice(&root.controller_address());
    values[1] = device_directory_commitment(&directory).unwrap().0;
    values[2][23] = 1;
    values[2][31] = 1;
    let signed = sign_record(
        &root,
        RecordPayload::DeviceDirectory(directory),
        1,
        now_ms,
        120_000,
    )
    .unwrap();
    fs::write(paths.signed_device_directory(), signed).unwrap();
    fs::write(
        paths.network_settings_configuration(),
        serde_json::to_vec(&NetworkSettingsV1 {
            loopback_groups: true,
            ..NetworkSettingsV1::default()
        })
        .unwrap(),
    )
    .unwrap();
    (peer, (root.agent_id(), values))
}

fn emit(value: Value) {
    let mut output = io::stdout().lock();
    writeln!(output, "{RESULT_PREFIX}{value}").unwrap();
    output.flush().unwrap();
}

fn parse_hex<const N: usize>(value: &Value) -> [u8; N] {
    alloy_primitives::hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

struct CoreProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
}

impl CoreProcess {
    fn start(home: &Path, registry: &Path) -> (Self, Value) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", CHILD, "--nocapture"])
            .env("ASL_GROUP_FIXTURE_HOME", home)
            .env("ASL_GROUP_FIXTURE_REGISTRY", registry)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (output, messages) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some((_, reply)) = line.split_once(RESULT_PREFIX)
                    && output.send(serde_json::from_str(reply).unwrap()).is_err()
                {
                    break;
                }
            }
        });
        let mut core = Self {
            child,
            input,
            output: messages,
        };
        let ready = core.receive();
        (core, ready)
    }

    fn receive(&mut self) -> Value {
        match self.output.recv_timeout(WAIT) {
            Ok(reply) => reply,
            Err(error) => panic!(
                "Core fixture output: {error:?}, child: {:?}",
                self.child.try_wait().unwrap()
            ),
        }
    }

    fn request(&mut self, action: Action) -> Value {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &action).unwrap();
        writeln!(input).unwrap();
        self.receive()
    }

    fn ok(&mut self, action: Action) -> Value {
        let value = self.request(action);
        assert!(value.get("error").is_none(), "{value}");
        value
    }

    fn dial(&mut self, ready: &Value, expected: &PeerId) {
        let endpoint: SocketAddr = ready["tcp"].as_str().unwrap().parse().unwrap();
        assert!(endpoint.ip().is_loopback());
        assert_ne!(endpoint.port(), 0);
        assert_eq!(
            self.ok(Action::Dial(endpoint, expected.as_bytes().to_vec()))["queued"],
            true
        );
    }

    fn connection(&mut self, peer: &Value) -> [u8; 16] {
        let find = |status: &Value| {
            status["connections"]
                .as_array()?
                .iter()
                .find(|entry| &entry["peer"] == peer)
                .map(|entry| parse_hex(&entry["connection"]))
        };
        let status = self.until(
            &format!("admission of {peer}"),
            || Action::Peers,
            |v| find(v).is_some(),
        );
        find(&status).unwrap()
    }

    fn invite(&mut self, room: Hash32, connection: [u8; 16], member: &mut Self, epoch: u64) {
        assert_eq!(self.ok(Action::Invite(room, connection))["queued"], true);
        let pending = member.until(
            "targeted invite",
            || Action::List,
            |v| v["pending"].as_array().is_some_and(|list| list.len() == 1),
        );
        assert_eq!(
            pending["pending"][0]["room"],
            alloy_primitives::hex::encode(room.0)
        );
        let invite = Id128(parse_hex(&pending["pending"][0]["id"]));
        assert_eq!(member.ok(Action::Approve(invite))["queued"], true);
        member.wait_epoch(room, epoch);
    }

    fn wait_epoch(&mut self, room: Hash32, epoch: u64) {
        let state = self.until_for(
            Duration::from_secs(52),
            "durable epoch",
            || Action::Room(room),
            |v| v["mls_epoch"] == epoch,
        );
        assert_eq!(state["state"], "needs_sync");
    }

    fn receive_query(&mut self, room: Hash32, sent: &Value, sender: &Value) -> Value {
        let view = self.until(
            "group message",
            || Action::Room(room),
            |v| v["last_received"]["message_id"] == sent["message_id"],
        );
        let received = &view["last_received"];
        assert_eq!(&received["sender"], sender);
        assert_eq!(received["kind"], "query");
        received.clone()
    }

    fn until(
        &mut self,
        stage: &str,
        action: impl Fn() -> Action,
        done: impl Fn(&Value) -> bool,
    ) -> Value {
        self.until_for(WAIT, stage, action, done)
    }

    fn until_for(
        &mut self,
        wait: Duration,
        stage: &str,
        action: impl Fn() -> Action,
        done: impl Fn(&Value) -> bool,
    ) -> Value {
        let deadline = Instant::now() + wait;
        loop {
            let reply = self.request(action());
            if done(&reply) {
                return reply;
            }
            assert!(Instant::now() < deadline, "{stage}: {reply}");
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn close(mut self) {
        drop(self.input.take());
        assert_eq!(
            self.output.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected)
        );
        assert!(self.child.wait().unwrap().success());
    }
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        drop(self.input.take());
        // Give Core time to restore the sandbox executable ACLs and delete its
        // AppContainer profile even when an assertion in the parent fails.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(25)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
