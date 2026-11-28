//! A real restricted child, not a mock security verdict.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
#[allow(dead_code)]
#[path = "../platform/windows/probe_support.rs"]
mod probe_support;

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::time::Duration;

    if std::env::args().any(|argument| argument == "--spawned") {
        std::process::exit(73);
    }
    let mut request = Vec::new();
    std::io::stdin().take(16_385).read_to_end(&mut request)?;
    if request.is_empty() || request.len() > 16_384 {
        std::process::exit(2);
    }
    let payload = &request[1..];
    let text = || {
        std::str::from_utf8(payload)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
    };
    let mut response = Vec::new();
    match request[0] {
        1 => match std::fs::read(text()?) {
            Ok(bytes) => {
                response.push(1);
                response.extend_from_slice(&bytes[..bytes.len().min(128)]);
            }
            Err(_) => response.push(0),
        },
        2 => {
            let address: SocketAddr = text()?
                .parse()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            response.push(u8::from(
                TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok(),
            ));
        }
        3 => {
            let result = std::env::current_exe()
                .and_then(|exe| std::process::Command::new(exe).arg("--spawned").spawn());
            response.push(u8::from(result.is_ok()));
            if let Ok(mut child) = result {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        4 => {
            let value = u64::from_le_bytes(
                payload
                    .try_into()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?,
            );
            response = probe_support::read_handle(value as usize);
        }
        5 => {
            response.push(u8::from(std::env::var_os("USERPROFILE").is_some()));
            response.push(u8::from(std::env::var_os("CARGO_HOME").is_some()));
            response.push(u8::from(std::env::var_os("RUSTUP_HOME").is_some()));
        }
        6 => {
            std::io::stdout().write_all(&[42])?;
            std::io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(60));
        }
        7 => loop {
            std::hint::black_box(
                (0..10_000u64).fold(1u64, |a, b| a.wrapping_mul(b).wrapping_add(7)),
            );
        },
        8 => {
            let size = u64::from_le_bytes(
                payload
                    .try_into()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?,
            );
            let mut bytes = vec![0u8; size as usize];
            bytes.fill(17);
            std::hint::black_box(&bytes);
            response.push(1);
        }
        9 => {
            let address: SocketAddr = text()?
                .parse()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            let payload = b"asl-t09-udp-probe-v1";
            let mut received = [0u8; 128];
            let echoed = UdpSocket::bind("0.0.0.0:0")
                .and_then(|socket| {
                    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                    socket.send_to(payload, address)?;
                    socket.recv_from(&mut received)
                })
                .is_ok_and(|(length, peer)| {
                    peer.ip() == address.ip()
                        && peer.port() == address.port()
                        && &received[..length] == payload
                });
            response.push(u8::from(echoed));
        }
        10 => {
            let result = UdpSocket::bind("0.0.0.0:0").and_then(|socket| {
                socket.join_multicast_v4(
                    &std::net::Ipv4Addr::new(224, 0, 0, 251),
                    &std::net::Ipv4Addr::UNSPECIFIED,
                )
            });
            response.push(u8::from(result.is_ok()));
        }
        _ => std::process::exit(2),
    }
    std::io::stdout().write_all(&response)?;
    std::io::stdout().flush()
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::time::Duration;

    if std::env::args().any(|argument| argument == "--spawned") {
        std::process::exit(73);
    }
    let mut request = Vec::new();
    std::io::stdin().take(16_385).read_to_end(&mut request)?;
    if request.is_empty() || request.len() > 16_384 {
        std::process::exit(2);
    }
    let payload = &request[1..];
    let text = || {
        std::str::from_utf8(payload)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
    };
    let mut response = Vec::new();
    match request[0] {
        1 => match std::fs::read(text()?) {
            Ok(bytes) => {
                response.push(1);
                response.extend_from_slice(&bytes[..bytes.len().min(128)]);
            }
            Err(_) => response.push(0),
        },
        2 => {
            let address: SocketAddr = text()?
                .parse()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            response.push(u8::from(
                TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok(),
            ));
        }
        3 => {
            let result = std::env::current_exe()
                .and_then(|exe| std::process::Command::new(exe).arg("--spawned").spawn());
            response.push(u8::from(result.is_ok()));
            if let Ok(mut child) = result {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        5 => {
            response.push(u8::from(std::env::var_os("HOME").is_some()));
            response.push(u8::from(std::env::var_os("CARGO_HOME").is_some()));
            response.push(u8::from(std::env::var_os("RUSTUP_HOME").is_some()));
        }
        6 => {
            std::io::stdout().write_all(&[42])?;
            std::io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(60));
        }
        7 => loop {
            std::hint::black_box(
                (0..10_000u64).fold(1u64, |a, b| a.wrapping_mul(b).wrapping_add(7)),
            );
        },
        8 => {
            let size = u64::from_le_bytes(
                payload
                    .try_into()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?,
            );
            let mut bytes = vec![0u8; size as usize];
            bytes.fill(17);
            std::hint::black_box(&bytes);
            response.push(1);
        }
        9 => {
            let address: SocketAddr = text()?
                .parse()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            let payload = b"asl-t09-udp-probe-v1";
            let mut received = [0u8; 128];
            let echoed = UdpSocket::bind("0.0.0.0:0")
                .and_then(|socket| {
                    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                    socket.send_to(payload, address)?;
                    socket.recv_from(&mut received)
                })
                .is_ok_and(|(length, peer)| {
                    peer.ip() == address.ip()
                        && peer.port() == address.port()
                        && &received[..length] == payload
                });
            response.push(u8::from(echoed));
        }
        10 => {
            let result = UdpSocket::bind("0.0.0.0:0").and_then(|socket| {
                socket.join_multicast_v4(
                    &std::net::Ipv4Addr::new(224, 0, 0, 251),
                    &std::net::Ipv4Addr::UNSPECIFIED,
                )
            });
            response.push(u8::from(result.is_ok()));
        }
        _ => std::process::exit(2),
    }
    std::io::stdout().write_all(&response)?;
    std::io::stdout().flush()
}

#[cfg(not(any(windows, target_os = "linux")))]
fn main() {
    std::process::exit(2);
}
