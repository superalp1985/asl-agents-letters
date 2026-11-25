use std::{
    io::{self, BufRead, BufReader},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    process::{Child, Command, Stdio},
};

use super::fresh_id;

pub(super) struct ReceiverRule(Child);

impl ReceiverRule {
    pub(super) fn open(program: &Path, endpoint: SocketAddr, sid: &str) -> io::Result<Self> {
        if endpoint.ip() != Ipv4Addr::LOCALHOST || endpoint.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a bound IPv4 loopback listener",
            ));
        }
        let run = match std::env::var("ASL_GROUP_FIREWALL_RUN") {
            Ok(run) => run,
            Err(_) => alloy_primitives::hex::encode(fresh_id().map_err(io::Error::other)?),
        };
        let system = std::env::var_os("SystemRoot").ok_or(io::ErrorKind::NotFound)?;
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/group-fixture-firewall.ps1");
        let mut child =
            Command::new(Path::new(&system).join("System32/WindowsPowerShell/v1.0/powershell.exe"))
                .args(["-NoProfile", "-NonInteractive", "-File"])
                .arg(script)
                .args(["-RunId", &run, "-Sid", sid, "-Port"])
                .arg(endpoint.port().to_string())
                .arg("-Program")
                .arg(program)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
        let output = child.stdout.take().expect("piped helper stdout");
        let guard = Self(child);
        let mut line = String::new();
        BufReader::new(output).read_line(&mut line)?;
        match helper_status(&line)? {
            true => {}
            false => eprintln!(
                "Host firewall profiles are disabled; relying on the verified AppContainer WFP loopback permit."
            ),
        }
        Ok(guard)
    }

    pub(super) fn close(&mut self) -> io::Result<()> {
        drop(self.0.stdin.take());
        let status = self.0.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("receiver rule helper: {status}")));
        }
        Ok(())
    }
}

fn helper_status(line: &str) -> io::Result<bool> {
    match line.trim_end() {
        "READY" => Ok(true),
        "FIREWALL_DISABLED" => Ok(false),
        _ => Err(io::Error::other(
            "Windows did not confirm the receiver rule",
        )),
    }
}

impl Drop for ReceiverRule {
    fn drop(&mut self) {
        if self.0.stdin.is_some()
            && let Err(error) = self.close()
        {
            eprintln!("Closing fixture firewall rule: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_status_distinguishes_enforced_rules_from_disabled_host_firewall() {
        assert!(matches!(helper_status("READY\r\n"), Ok(true)));
        assert!(matches!(helper_status("FIREWALL_DISABLED\r\n"), Ok(false)));
        assert!(helper_status("unexpected output\r\n").is_err());
    }
}
