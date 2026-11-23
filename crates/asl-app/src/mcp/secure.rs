use std::{io, time::Duration};

use asl_types::error::AslError;
use serde::{Serialize, de::DeserializeOwned};
use snow::{Builder, TransportState};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

const PROTOCOL: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"ASL local MCP IPC v1";
const HANDSHAKE_BYTES: usize = 48; // X25519 e + authentication tag; no payload.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(3);
const MAX_RECORD_BYTES: usize = u16::MAX as usize;
const TAG_BYTES: usize = 16;

pub(super) struct SecurePipe<S> {
    stream: S,
    noise: TransportState,
    header: [u8; 2],
    encrypted: Vec<u8>,
    read: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecurePipe<S> {
    pub async fn initiate(stream: S, key: &[u8; 32]) -> Result<Self, AslError> {
        Self::establish(stream, key, true).await
    }

    pub async fn respond(stream: S, key: &[u8; 32]) -> Result<Self, AslError> {
        Self::establish(stream, key, false).await
    }

    async fn establish(mut stream: S, key: &[u8; 32], initiator: bool) -> Result<Self, AslError> {
        let exchange = async {
            let builder = Builder::new(PROTOCOL.parse().map_err(|_| AslError::InvalidPolicyState)?)
                .prologue(PROLOGUE)
                .and_then(|builder| builder.psk(0, key))
                .map_err(|_| AslError::InvalidPolicyState)?;
            let mut handshake = if initiator {
                builder.build_initiator()
            } else {
                builder.build_responder()
            }
            .map_err(|_| AslError::InvalidPolicyState)?;
            let mut message = [0; HANDSHAKE_BYTES];
            // Use a fixed, payload-free handshake, then the SDK's stateful
            // authenticated records. The PSK is never sent on the pipe.
            for write in [initiator, !initiator] {
                if write {
                    let len = handshake
                        .write_message(&[], &mut message)
                        .map_err(|_| AslError::PolicyDenied)?;
                    if len != message.len() {
                        return Err(AslError::InvalidPolicyState);
                    }
                    stream.write_all(&message).await?;
                } else {
                    stream.read_exact(&mut message).await?;
                    handshake
                        .read_message(&message, &mut [])
                        .map_err(|_| AslError::PolicyDenied)?;
                }
            }
            handshake
                .into_transport_mode()
                .map_err(|_| AslError::PolicyDenied)
        };
        let noise = timeout(HANDSHAKE_DEADLINE, exchange)
            .await
            .map_err(|_| AslError::PolicyDenied)??;
        Ok(Self {
            stream,
            noise,
            header: [0; 2],
            encrypted: Vec::new(),
            read: 0,
        })
    }

    pub async fn send(&mut self, value: &impl Serialize) -> Result<(), AslError> {
        let plain = serde_json::to_vec(value).map_err(|_| AslError::InvalidMessage)?;
        if plain.len() > MAX_RECORD_BYTES - TAG_BYTES {
            return Err(AslError::QuotaExceeded);
        }
        let mut encrypted = vec![0; plain.len() + TAG_BYTES];
        let len = self
            .noise
            .write_message(&plain, &mut encrypted)
            .map_err(|_| AslError::InvalidMessage)?;
        self.stream.write_u16(len as u16).await?;
        self.stream.write_all(&encrypted[..len]).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T, AslError> {
        // A select may stop polling this reader for a write. Keep framing
        // progress on the pipe and advance the Noise nonce only on a full record.
        while self.read < self.header.len() {
            let n = self.stream.read(&mut self.header[self.read..]).await?;
            self.add_read(n)?;
        }
        if self.encrypted.is_empty() {
            let len = u16::from_be_bytes(self.header) as usize;
            if len <= TAG_BYTES {
                return Err(io::Error::from(io::ErrorKind::InvalidData).into());
            }
            self.encrypted.resize(len, 0);
        }
        while self.read - self.header.len() < self.encrypted.len() {
            let offset = self.read - self.header.len();
            let n = self.stream.read(&mut self.encrypted[offset..]).await?;
            self.add_read(n)?;
        }
        let mut plain = vec![0; self.encrypted.len() - TAG_BYTES];
        let len = self
            .noise
            .read_message(&self.encrypted, &mut plain)
            .map_err(|_| AslError::PolicyDenied)?;
        self.read = 0;
        self.encrypted.clear();
        serde_json::from_slice(&plain[..len]).map_err(|_| AslError::InvalidMessage)
    }

    fn add_read(&mut self, n: usize) -> Result<(), AslError> {
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        self.read += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn matching_key_allows_encrypted_records_in_both_directions() {
        let (a, b) = tokio::io::duplex(128);
        let key = [42; 32];
        let (a, b) = tokio::join!(SecurePipe::initiate(a, &key), SecurePipe::respond(b, &key));
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        a.send(&42).await.unwrap();
        assert_eq!(b.receive::<u32>().await.unwrap(), 42);
        b.send(&43).await.unwrap();
        assert_eq!(a.receive::<u32>().await.unwrap(), 43);
    }

    #[tokio::test]
    async fn different_keys_do_not_open_an_attachment() {
        let (a, b) = tokio::io::duplex(128);
        let (a, b) = tokio::join!(
            SecurePipe::initiate(a, &[42; 32]),
            SecurePipe::respond(b, &[43; 32]),
        );
        assert!(a.is_err());
        assert!(matches!(b, Err(AslError::PolicyDenied)));
    }

    #[tokio::test]
    async fn receive_resumes_after_select_interrupts_a_partial_record() {
        let (a, b) = tokio::io::duplex(8);
        let key = [42; 32];
        let (a, b) = tokio::join!(SecurePipe::initiate(a, &key), SecurePipe::respond(b, &key));
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        let message = "message longer than the pipe buffer";
        let mut send = std::pin::pin!(a.send(&message));
        // Each side runs until blocked on the other side. Interrupt the read
        // after consuming bytes, without closing the authenticated pipe.
        tokio::select! {
            biased;
            _ = &mut send => panic!("record unexpectedly fit in pipe"),
            _ = b.receive::<String>() => panic!("record unexpectedly arrived"),
            _ = std::future::ready(()) => {}
        }
        assert!(b.read > b.header.len());
        let (send, received) = tokio::join!(send, b.receive::<String>());
        send.unwrap();
        assert_eq!(received.unwrap(), "message longer than the pipe buffer");
    }
}
