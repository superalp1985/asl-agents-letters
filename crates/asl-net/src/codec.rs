//! Wire framing only. The driver must separately authorize traffic and bind replies to requests.

use std::io;

use asl_types::protocol::{
    IdentityProof, IdentityProofRequest, MAX_CONTROL_FRAME_BYTES, MAX_EXTENDED_FRAME_BYTES,
    WireFrame, decode_control, decode_frame, encode_control, encode_frame,
};

mod bulk;
pub use bulk::{BULK_PROTOCOL, BulkCodec, BulkOperation, BulkRequest, BulkResponse, BulkStatus};
use libp2p::{
    StreamProtocol,
    futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response::Codec,
};

pub const CONTROL_PROTOCOL: StreamProtocol = StreamProtocol::new("/asl/control/1.0.0");
pub const IDENTITY_PROOF_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/asl/identity-proof/1.1.0");

// Canonical CBOR map with five one-byte keys, two one-byte values, and three fixed byte strings.
const PROOF_REQUEST_BYTES: usize = 1 + 5 + 2 + (1 + 16) + (2 + 32) + (2 + 32);

#[derive(Clone, Copy, Debug, Default)]
pub struct ControlCodec;

impl Codec for ControlCodec {
    type Protocol = StreamProtocol;
    type Request = WireFrame;
    type Response = WireFrame;

    async fn read_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<WireFrame>
    where
        T: AsyncRead + Unpin + Send,
    {
        check_protocol(protocol, CONTROL_PROTOCOL)?;
        let bytes = read_payload(io, MAX_CONTROL_FRAME_BYTES).await?;
        decode_control(&bytes).map_err(|_| io::ErrorKind::InvalidData.into())
    }

    async fn read_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<WireFrame>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_request(protocol, io).await
    }

    async fn write_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        request: WireFrame,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        check_protocol(protocol, CONTROL_PROTOCOL)?;
        let bytes = encode_control(&request).map_err(|_| io::ErrorKind::InvalidInput)?;
        write_payload(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        response: WireFrame,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_request(protocol, io, response).await
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityProofCodec;

impl Codec for IdentityProofCodec {
    type Protocol = StreamProtocol;
    type Request = IdentityProofRequest;
    type Response = IdentityProof;

    async fn read_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<IdentityProofRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        check_protocol(protocol, IDENTITY_PROOF_PROTOCOL)?;
        let bytes = read_payload(io, PROOF_REQUEST_BYTES).await?;
        match decode_frame(&bytes) {
            Ok(WireFrame::IdentityProofRequest(request)) => Ok(request),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    async fn read_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<IdentityProof>
    where
        T: AsyncRead + Unpin + Send,
    {
        check_protocol(protocol, IDENTITY_PROOF_PROTOCOL)?;
        let bytes = read_payload(io, MAX_EXTENDED_FRAME_BYTES).await?;
        match decode_frame(&bytes) {
            Ok(WireFrame::IdentityProof(proof)) => Ok(proof),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    async fn write_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        request: IdentityProofRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        check_protocol(protocol, IDENTITY_PROOF_PROTOCOL)?;
        let bytes = encode_frame(&WireFrame::IdentityProofRequest(request))
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        write_payload(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        response: IdentityProof,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        check_protocol(protocol, IDENTITY_PROOF_PROTOCOL)?;
        let bytes = encode_frame(&WireFrame::IdentityProof(response))
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        write_payload(io, &bytes).await
    }
}

fn check_protocol(protocol: &StreamProtocol, expected: StreamProtocol) -> io::Result<()> {
    if *protocol == expected {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidInput.into())
    }
}

async fn read_payload<T: AsyncRead + Unpin>(io: &mut T, limit: usize) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    io.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut payload = vec![0; length];
    io.read_exact(&mut payload).await?;
    require_eof(io).await?;
    Ok(payload)
}

async fn require_eof<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<()> {
    // libp2p request-response closes the sending half after each message.
    if io.read(&mut [0]).await? != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

async fn write_payload<T: AsyncWrite + Unpin>(io: &mut T, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(bytes).await
}
