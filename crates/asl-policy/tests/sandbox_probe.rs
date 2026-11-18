#![cfg(windows)]

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use asl_policy::sandbox::{
    InheritedPipes, SandboxChild, SandboxLauncher, SandboxLimits, SandboxRole,
};
use asl_types::error::AslError;

#[allow(dead_code)]
#[path = "../src/platform/windows/probe_support.rs"]
mod probe_support;

static NEXT: AtomicU64 = AtomicU64::new(0);
const SECRET: &[u8] = b"asl-private-sentinel-never-share";

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    program: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = match std::env::var_os("ASL_T09_FIXTURE_BASE") {
            Some(base) => PathBuf::from(base),
            None => {
                let base = std::env::temp_dir().join("asl-test-fs");
                fs::create_dir_all(&base).unwrap();
                base
            }
        };
        assert!(
            base.is_absolute() && base.is_dir(),
            "fixture base must exist"
        );
        assert!(
            !fs::symlink_metadata(&base)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let root = base.join(format!(
            "t09-sandbox-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let program = root.join("sandbox probe.exe");
        fs::copy(env!("CARGO_BIN_EXE_asl-sandbox-probe"), &program).unwrap();
        fs::write(root.join("secret.md"), SECRET).unwrap();
        Self {
            base,
            root,
            program,
        }
    }

    fn launcher(&self) -> SandboxLauncher {
        SandboxLauncher::new(
            self.program.clone(),
            self.program.clone(),
            self.program.clone(),
        )
        .unwrap()
    }

    fn run(&self, role: SandboxRole, request: &[u8], limits: SandboxLimits) -> (u32, Vec<u8>) {
        let (mut pipes, inherited) = InheritedPipes::new().unwrap();
        let mut child = self
            .launcher()
            .spawn_sandbox(role, inherited, limits)
            .unwrap_or_else(|error| panic!("real sandbox must launch: {error:?}"));
        pipes.input.write_all(request).unwrap();
        drop(pipes.input);
        let code = child
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .expect("child must terminate");
        let mut output = Vec::new();
        pipes.output.read_to_end(&mut output).unwrap();
        let mut errors = String::new();
        pipes.error.take(4096).read_to_string(&mut errors).unwrap();
        eprintln!(
            "SANDBOX_EXERCISED role={role:?} op={} exit={code} stderr={errors:?}",
            request[0]
        );
        (code, output)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(self.root.parent(), Some(self.base.as_path()));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("t09-sandbox-")
        );
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove only owned sandbox fixture");
        }
    }
}

struct SharedAclLauncher {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl SharedAclLauncher {
    fn start(test_executable: &Path, shared_executable: &Path) -> Self {
        let mut child = Command::new(test_executable)
            .arg("shared_acl_launch_child")
            .arg("--nocapture")
            .env("ASL_T09_SHARED_ACL_EXECUTABLE", shared_executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }

    fn message(&mut self) -> String {
        loop {
            let mut line = String::new();
            self.output.read_line(&mut line).unwrap();
            let message = line.trim();
            if matches!(message, "ready" | "complete") {
                return message.to_owned();
            }
        }
    }

    fn release(&mut self) {
        self.input.write_all(b"go\n").unwrap();
        self.input.flush().unwrap();
    }
}

impl Drop for SharedAclLauncher {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn parallel_processes_preserve_executable_acl_updates() {
    let fixture = Fixture::new();
    let before = probe_support::dacl(&File::open(&fixture.program).unwrap());
    let test_executable = std::env::current_exe().unwrap();
    let mut first = SharedAclLauncher::start(&test_executable, &fixture.program);
    assert_eq!(first.message(), "ready");
    let mut second = SharedAclLauncher::start(&test_executable, &fixture.program);
    assert_eq!(second.message(), "ready");

    first.release();
    second.release();
    assert_eq!(first.message(), "complete");
    assert_eq!(second.message(), "complete");
    assert!(first.child.wait().unwrap().success());
    assert!(second.child.wait().unwrap().success());
    assert_eq!(
        probe_support::dacl(&File::open(&fixture.program).unwrap()),
        before
    );
}

#[test]
fn shared_acl_launch_child() {
    let Some(program) = std::env::var_os("ASL_T09_SHARED_ACL_EXECUTABLE") else {
        return;
    };
    println!("ready");
    std::io::stdout().flush().unwrap();
    let mut release = String::new();
    std::io::stdin().lock().read_line(&mut release).unwrap();
    assert_eq!(release.trim(), "go");

    let program = PathBuf::from(program);
    let launcher = SandboxLauncher::new(program.clone(), program.clone(), program).unwrap();
    for _ in 0..3 {
        let (mut pipes, inherited) = InheritedPipes::new().unwrap();
        let mut child = launcher
            .spawn_sandbox(
                SandboxRole::Worker,
                inherited,
                SandboxLimits::for_role(SandboxRole::Worker),
            )
            .unwrap();
        drop(pipes.error);
        pipes.input.write_all(&[5]).unwrap();
        drop(pipes.input);
        assert_eq!(
            child.wait_timeout(Duration::from_secs(10)).unwrap(),
            Some(0)
        );
        let mut response = Vec::new();
        pipes.output.read_to_end(&mut response).unwrap();
        assert_eq!(response, [0, 0, 0]);
    }
    println!("complete");
}

fn request(op: u8, value: &Path) -> Vec<u8> {
    let mut bytes = vec![op];
    bytes.extend_from_slice(value.to_str().unwrap().as_bytes());
    bytes
}

#[test]
fn worker_and_extractor_cannot_read_outside_files_or_spawn_children() {
    let fixture = Fixture::new();
    assert_eq!(fs::read(fixture.root.join("secret.md")).unwrap(), SECRET);
    for role in [SandboxRole::Worker, SandboxRole::Extractor] {
        for query in [request(1, &fixture.root.join("secret.md")), vec![3]] {
            assert_eq!(
                fixture.run(role, &query, SandboxLimits::for_role(role)),
                (0, vec![0])
            );
        }
    }
}

#[test]
fn no_role_can_read_user_fixture_even_net_with_network_capabilities() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.run(
            SandboxRole::Net,
            &request(1, &fixture.root.join("secret.md")),
            SandboxLimits::for_role(SandboxRole::Net)
        ),
        (0, vec![0])
    );
}

#[test]
fn worker_cannot_connect_to_real_http_listener() {
    let fixture = Fixture::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut query = vec![2];
    query.extend_from_slice(listener.local_addr().unwrap().to_string().as_bytes());
    assert_eq!(
        fixture.run(
            SandboxRole::Worker,
            &query,
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        (0, vec![0])
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn extra_inheritable_file_handle_is_excluded_from_child() {
    let fixture = Fixture::new();
    let file = File::open(fixture.root.join("secret.md")).unwrap();
    probe_support::make_inheritable(&file);
    let mut query = vec![4];
    query.extend_from_slice(&(file.as_raw_handle() as u64).to_le_bytes());
    let (code, output) = fixture.run(
        SandboxRole::Worker,
        &query,
        SandboxLimits::for_role(SandboxRole::Worker),
    );
    // Some Windows handle-check policies raise STATUS_INVALID_HANDLE instead
    // of returning a Win32 error for the deliberately unlisted handle value.
    assert!(code == 0 || code == 0xC000_0008);
    assert!(output.is_empty(), "unlisted handle must not read any bytes");
}

#[test]
fn inherited_user_environment_is_cleared() {
    let fixture = Fixture::new();
    assert!(std::env::var_os("USERPROFILE").is_some());
    assert_eq!(
        fixture.run(
            SandboxRole::Worker,
            &[5],
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        (0, vec![0, 0, 0])
    );
}

#[test]
fn broker_pipe_handles_are_not_inheritable() {
    let (broker, _) = InheritedPipes::new().unwrap();
    for pipe in [&broker.input, &broker.output, &broker.error] {
        assert!(!probe_support::is_inheritable(pipe));
    }
}

#[test]
fn wall_deadline_terminates_blocked_worker() {
    let fixture = Fixture::new();
    let mut limits = SandboxLimits::for_role(SandboxRole::Worker);
    limits.wall_time_ms = Some(500);
    let (code, output) = fixture.run(SandboxRole::Worker, &[6], limits);
    assert_ne!(code, 0);
    assert_eq!(output, [42]);
}

#[test]
fn cpu_deadline_terminates_busy_worker() {
    let fixture = Fixture::new();
    let mut limits = SandboxLimits::for_role(SandboxRole::Worker);
    limits.cpu_time_ms = Some(100);
    limits.cpu_rate_percent = 100;
    let (code, _) = fixture.run(SandboxRole::Worker, &[7], limits);
    assert_ne!(code, 0);
}

#[test]
fn memory_limit_rejects_large_allocation() {
    let fixture = Fixture::new();
    let mut limits = SandboxLimits::for_role(SandboxRole::Worker);
    limits.memory_bytes = 32 * 1024 * 1024;
    let mut query = vec![8];
    query.extend_from_slice(&(128 * 1024 * 1024u64).to_le_bytes());
    let (code, output) = fixture.run(SandboxRole::Worker, &query, limits);
    assert_ne!(code, 0);
    assert!(output.is_empty());
}

#[test]
fn dropping_child_terminates_process() {
    let fixture = Fixture::new();
    let (mut pipes, inherited) = InheritedPipes::new().unwrap();
    let child: SandboxChild = fixture
        .launcher()
        .spawn_sandbox(
            SandboxRole::Net,
            inherited,
            SandboxLimits::for_role(SandboxRole::Net),
        )
        .unwrap();
    pipes.input.write_all(&[6]).unwrap();
    drop(pipes.input);
    let mut ready = [0];
    pipes.output.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [42]);
    let id = child.id();
    assert!(!probe_support::wait_process(id, Duration::ZERO));
    drop(child);
    assert!(probe_support::wait_process(id, Duration::from_secs(1)));
}

#[test]
fn invalid_program_and_limits_fail_without_unrestricted_fallback() {
    let fixture = Fixture::new();
    let missing = fixture.root.join("missing.exe");
    let launcher = SandboxLauncher::new(missing.clone(), missing.clone(), missing).unwrap();
    let (_, inherited) = InheritedPipes::new().unwrap();
    assert!(matches!(
        launcher.spawn_sandbox(
            SandboxRole::Worker,
            inherited,
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        Err(AslError::SandboxUnavailable)
    ));
    let mut limits = SandboxLimits::for_role(SandboxRole::Worker);
    limits.wall_time_ms = None;
    let (_, inherited) = InheritedPipes::new().unwrap();
    assert!(matches!(
        fixture
            .launcher()
            .spawn_sandbox(SandboxRole::Worker, inherited, limits),
        Err(AslError::SandboxUnavailable)
    ));
}

#[test]
fn only_executable_acl_changes_and_is_restored_after_success_or_failure() {
    let fixture = Fixture::new();
    let executable_before = probe_support::dacl(&File::open(&fixture.program).unwrap());
    let directory = File::options()
        .read(true)
        .custom_flags(0x0200_0000)
        .open(&fixture.root)
        .unwrap();
    let directory_before = probe_support::dacl(&directory);
    assert_eq!(
        fixture.run(
            SandboxRole::Worker,
            &[5],
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        (0, vec![0, 0, 0])
    );
    assert_eq!(
        probe_support::dacl(&File::open(&fixture.program).unwrap()),
        executable_before
    );
    assert_eq!(probe_support::dacl(&directory), directory_before);

    let invalid = fixture.root.join("invalid.exe");
    fs::write(&invalid, b"not a PE executable").unwrap();
    let invalid_before = probe_support::dacl(&File::open(&invalid).unwrap());
    let launcher = SandboxLauncher::new(invalid.clone(), invalid.clone(), invalid.clone()).unwrap();
    let (_, inherited) = InheritedPipes::new().unwrap();
    assert!(
        launcher
            .spawn_sandbox(
                SandboxRole::Worker,
                inherited,
                SandboxLimits::for_role(SandboxRole::Worker)
            )
            .is_err()
    );
    assert_eq!(
        probe_support::dacl(&File::open(invalid).unwrap()),
        invalid_before
    );
    assert_eq!(probe_support::dacl(&directory), directory_before);
}

/// Requires an explicitly selected reachable TCP endpoint outside this host.
/// Opt-in prevents an offline unit-test run from impersonating network acceptance.
#[test]
#[ignore = "requires ASL_T09_TCP_TARGET for an external TCP endpoint"]
fn net_connects_to_same_external_target_that_worker_cannot_reach() {
    let target: std::net::SocketAddr = std::env::var("ASL_T09_TCP_TARGET")
        .expect("set ASL_T09_TCP_TARGET=host-address:port")
        .parse()
        .unwrap();
    assert!(!target.ip().is_loopback() && !target.ip().is_unspecified());
    let fixture = Fixture::new();
    let mut query = vec![2];
    query.extend_from_slice(target.to_string().as_bytes());
    assert_eq!(
        fixture.run(
            SandboxRole::Net,
            &query,
            SandboxLimits::for_role(SandboxRole::Net)
        ),
        (0, vec![1])
    );
    assert_eq!(
        fixture.run(
            SandboxRole::Worker,
            &query,
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        (0, vec![0])
    );
}

#[test]
fn net_multicast_membership_is_available() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.run(
            SandboxRole::Net,
            &[10],
            SandboxLimits::for_role(SandboxRole::Net)
        ),
        (0, vec![1])
    );
}

#[test]
fn worker_udp_denial_is_reported_as_a_structured_negative_result() {
    let fixture = Fixture::new();
    let mut query = vec![9];
    query.extend_from_slice(b"192.0.2.1:9");
    assert_eq!(
        fixture.run(
            SandboxRole::Worker,
            &query,
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        (0, vec![0])
    );
}

#[test]
#[ignore = "requires ASL_T09_UDP_TARGET for a controlled UDP receiver"]
fn net_sends_udp_datagram_to_explicit_external_receiver() {
    let target: std::net::SocketAddr = std::env::var("ASL_T09_UDP_TARGET")
        .expect("set ASL_T09_UDP_TARGET=host-address:port")
        .parse()
        .unwrap();
    assert!(!target.ip().is_loopback() && !target.ip().is_unspecified());
    let fixture = Fixture::new();
    let mut query = vec![9];
    query.extend_from_slice(target.to_string().as_bytes());
    assert_eq!(
        fixture.run(
            SandboxRole::Net,
            &query,
            SandboxLimits::for_role(SandboxRole::Net)
        ),
        (0, vec![1])
    );
    assert_eq!(
        fixture.run(
            SandboxRole::Worker,
            &query,
            SandboxLimits::for_role(SandboxRole::Worker)
        ),
        (0, vec![0])
    );
}
