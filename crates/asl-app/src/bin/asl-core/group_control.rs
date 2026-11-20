use std::{
    io::{self, BufRead, Cursor, IsTerminal, Read, Write},
    net::SocketAddr,
    sync::mpsc::{SyncSender, sync_channel},
    thread,
};

use alloy_primitives::hex;
use asl_app::supervisor::{
    LocalGroupAction, LocalGroupCommand, run_with_local_groups_from_environment,
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
};

const MAX_LINE: usize = 512;
const MAX_REPLY: usize = 64 * 1024;
const HELP: &str = "\
list | peers | create | room <room-id>
approve <invite-id> | retry <invite-id> | reject <invite-id>
invite <room-id> <connection-id> | dial <ip:port> <base58-peer-id>
Room, connection and invite IDs are hex. Dial uses TCP.
Approve saves the decision and tries once; use retry if needed.";

pub(super) fn run() -> Result<(), AslError> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(AslError::PolicyDenied);
    }
    let (commands, receiver) = sync_channel(1);
    // Keep blocking terminal input off the supervisor; it must be able to exit
    // on startup failure even while the operator is waiting at the prompt.
    thread::Builder::new()
        .name("asl-group-console".into())
        .spawn(move || {
            if console(stdin.lock(), commands).is_err() {
                let _ = writeln!(io::stderr(), "Group console I/O failed.");
            }
        })?;
    run_with_local_groups_from_environment(receiver)
}

fn console(mut input: impl BufRead, commands: SyncSender<LocalGroupCommand>) -> io::Result<()> {
    let mut line = Vec::with_capacity(MAX_LINE + 1);
    let mut buffer = vec![0; MAX_REPLY];
    let mut output = io::stdout();
    let mut errors = io::stderr();
    writeln!(errors, "{HELP}")?;
    loop {
        line.clear();
        if input
            .by_ref()
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)?
            == 0
        {
            return Ok(());
        }
        if line.len() > MAX_LINE {
            if !line.ends_with(b"\n") {
                input.skip_until(b'\n')?;
            }
            writeln!(errors, "Command too long; discarded.")?;
            continue;
        }
        let text = std::str::from_utf8(&line).map(str::trim_ascii);
        let action = match text {
            Ok("") => continue,
            Ok("help") => {
                writeln!(errors, "{HELP}")?;
                continue;
            }
            Ok(text) => parse(text),
            Err(_) => Err(AslError::InvalidMessage),
        };
        let Ok(action) = action else {
            writeln!(errors, "Invalid group command. Type help for syntax.")?;
            continue;
        };
        let (reply, response) = sync_channel(1);
        if commands.send(LocalGroupCommand { action, reply }).is_err() {
            return Ok(());
        }
        match response.recv() {
            Ok(Ok(value)) => {
                let mut encoded = Cursor::new(buffer.as_mut_slice());
                if serde_json::to_writer(&mut encoded, &value).is_err() {
                    writeln!(errors, "Command completed; reply too large to display.")?;
                    continue;
                }
                let len = encoded.position() as usize;
                output.write_all(&buffer[..len])?;
                writeln!(output)?;
                output.flush()?;
            }
            Ok(Err(AslError::Io(error))) => {
                writeln!(errors, "Group I/O error: {:?}", error.kind())?
            }
            Ok(Err(error)) => writeln!(errors, "{error}")?,
            Err(_) => return Ok(()),
        }
    }
}

fn parse(line: &str) -> Result<LocalGroupAction, AslError> {
    let words: Vec<_> = line.split_ascii_whitespace().take(4).collect();
    let action = match words.as_slice() {
        ["list"] => LocalGroupAction::List,
        ["peers"] => LocalGroupAction::Peers,
        ["create"] => LocalGroupAction::Create,
        ["room", id] => LocalGroupAction::Room(Hash32(fixed_hex(id)?)),
        ["approve", id] => LocalGroupAction::Approve(Id128(fixed_hex(id)?)),
        ["retry", id] => LocalGroupAction::Retry(Id128(fixed_hex(id)?)),
        ["reject", id] => LocalGroupAction::Reject(Id128(fixed_hex(id)?)),
        ["invite", room, connection] => LocalGroupAction::Invite {
            room: Hash32(fixed_hex(room)?),
            connection_id: fixed_hex(connection)?,
        },
        ["dial", address, peer] => {
            let address: SocketAddr = address.parse().map_err(|_| AslError::InvalidMessage)?;
            if address.port() == 0 {
                return Err(AslError::InvalidMessage);
            }
            let peer: libp2p_identity::PeerId =
                peer.parse().map_err(|_| AslError::InvalidMessage)?;
            LocalGroupAction::Dial {
                address,
                peer: PeerId::from_bytes(peer.to_bytes()).map_err(|_| AslError::InvalidMessage)?,
            }
        }
        _ => return Err(AslError::InvalidMessage),
    };
    Ok(action)
}

fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N], AslError> {
    let mut bytes = [0; N];
    if text.len() != N * 2 || hex::decode_to_slice(text, &mut bytes).is_err() {
        return Err(AslError::InvalidMessage);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_actions_and_exact_ids() {
        let id = "ab".repeat(16);
        let room_id = "cd".repeat(32);
        assert!(matches!(parse("list"), Ok(LocalGroupAction::List)));
        assert!(matches!(parse("peers"), Ok(LocalGroupAction::Peers)));
        assert!(matches!(parse("create"), Ok(LocalGroupAction::Create)));
        assert!(
            matches!(parse(&format!("approve {id}")), Ok(LocalGroupAction::Approve(Id128(n))) if n == [0xab; 16])
        );
        assert!(
            matches!(parse(&format!("retry {id}")), Ok(LocalGroupAction::Retry(Id128(n))) if n == [0xab; 16])
        );
        assert!(
            matches!(parse(&format!("reject {id}")), Ok(LocalGroupAction::Reject(Id128(n))) if n == [0xab; 16])
        );
        assert!(matches!(
            parse(&format!("invite {room_id} {id}")),
            Ok(LocalGroupAction::Invite { room: Hash32(n), connection_id }) if n == [0xcd; 32] && connection_id == [0xab; 16]
        ));
    }

    #[test]
    fn dial_requires_a_socket_address_and_peer_identity() {
        let peer = libp2p_identity::Keypair::ed25519_from_bytes([7; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let address = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 12345));
        assert!(matches!(
            parse(&format!("dial {address} {peer}")),
            Ok(LocalGroupAction::Dial { address: got, peer: id }) if got == address && id.as_bytes() == peer.to_bytes()
        ));
        for invalid in ["localhost:12345", "udp://[::1]:12345", "[::1]:0"] {
            assert!(parse(&format!("dial {invalid} {peer}")).is_err());
        }
        assert!(parse(&format!("dial {address} not-a-peer")).is_err());
    }

    #[test]
    fn rejects_unknown_commands_bad_ids_and_extra_arguments() {
        let id = "ab".repeat(16);
        for invalid in [
            "approve".to_owned(),
            "list extra".into(),
            format!("approve {id} extra"),
            format!("retry {}", "zz".repeat(16)),
            format!("reject {id}00"),
            format!("invite {id} {id}"),
            format!("invite {} {id} extra", "cd".repeat(32)),
            "send".into(),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
}
