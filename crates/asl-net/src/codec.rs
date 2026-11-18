//! Wire framing only. The driver must separately authorize traffic and bind replies to requests.

use std::io;

use asl_types::ids::{Hash32, Id128};
use asl_types::protocol::{
    IdentityProof, IdentityProofRequest, MAX_CONTROL_FRAME_BYTES, MAX_EXTENDED_FRAME_BYTES,
    WireFrame, decode_control, decode_frame, encode_control, encode_frame,
};
use libp2p::{
    StreamProtocol,
    futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response::Codec,
};

pub const CONTROL_PROTOCOL: StreamProtocol = StreamProtocol::new("/asl/control/1.0.0");
pub const IDENTITY_PROOF_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/asl/identity-proof/1.0.0");
pub const BULK_PROTOCOL: StreamProtocol = StreamProtocol::new("/asl/blob/1.0.0");

// Canonical CBOR map with five one-byte keys, two one-byte values, and three fixed byte strings.
const PROOF_REQUEST_BYTES: usize = 1 + 5 + 2 + (1 + 16) + (2 + 32) + (2 + 32);
const BULK_REQUEST_BYTES: usize = 91;
const BULK_RESPONSE_HEADER_BYTES: usize = 27;
const MAX_BULK_PAYLOAD_BYTES: usize = 2_097_210;
const MAX_BULK_RESPONSE_BYTES: usize = BULK_RESPONSE_HEADER_BYTES + MAX_BULK_PAYLOAD_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BulkOperation {
    Manifest,
    Chunk,
    Inline,
}

impl BulkOperation {
    fn code(self) -> u8 {
        match self {
            Self::Manifest => 1,
            Self::Chunk => 2,
            Self::Inline => 3,
        }
    }

    fn from_code(code: u8) -> io::Result<Self> {
        match code {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::Chunk),
            3 => Ok(Self::Inline),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkRequest {
    pub operation: BulkOperation,
    pub request_id: Id128,
    pub content_id: Hash32,
    pub lease_id: Hash32,
    pub chunk_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BulkStatus {
    Success,
    NotFound,
    Busy,
    Expired,
    IntegrityFailed,
    Cancelled,
}

impl BulkStatus {
    fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::NotFound => 1,
            Self::Busy => 2,
            Self::Expired => 3,
            Self::IntegrityFailed => 4,
            Self::Cancelled => 5,
        }
    }

    fn from_code(code: u8) -> io::Result<Self> {
        match code {
            0 => Ok(Self::Success),
            1 => Ok(Self::NotFound),
            2 => Ok(Self::Busy),
            3 => Ok(Self::Expired),
            4 => Ok(Self::IntegrityFailed),
            5 => Ok(Self::Cancelled),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkResponse {
    pub request_id: Id128,
    pub status: BulkStatus,
    pub payload: Vec<u8>,
}

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

#[derive(Clone, Copy, Debug, Default)]
pub struct BulkCodec;

impl Codec for BulkCodec {
    type Protocol = StreamProtocol;
    type Request = BulkRequest;
    type Response = BulkResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<BulkRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        check_protocol(protocol, BULK_PROTOCOL)?;
        let mut bytes = [0; BULK_REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        if io.read(&mut [0]).await? != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        decode_bulk_request(&bytes)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<BulkResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        check_protocol(protocol, BULK_PROTOCOL)?;
        let mut prefix = [0; 4];
        io.read_exact(&mut prefix).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        if !(BULK_RESPONSE_HEADER_BYTES..=MAX_BULK_RESPONSE_BYTES).contains(&length) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = vec![0; length];
        io.read_exact(&mut bytes).await?;
        if io.read(&mut [0]).await? != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        decode_bulk_response(&bytes)
    }

    async fn write_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        request: BulkRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        check_protocol(protocol, BULK_PROTOCOL)?;
        let bytes = encode_bulk_request(&request)?;
        io.write_all(&bytes).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        response: BulkResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        check_protocol(protocol, BULK_PROTOCOL)?;
        let bytes = encode_bulk_response(&response)?;
        let length = u32::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&bytes).await
    }
}

fn encode_bulk_request(request: &BulkRequest) -> io::Result<[u8; BULK_REQUEST_BYTES]> {
    validate_bulk_index(
        request.operation,
        request.chunk_index,
        io::ErrorKind::InvalidInput,
    )?;
    let mut bytes = [0; BULK_REQUEST_BYTES];
    bytes[..6].copy_from_slice(b"ASLB01");
    bytes[6] = request.operation.code();
    bytes[7..23].copy_from_slice(&request.request_id.0);
    bytes[23..55].copy_from_slice(&request.content_id.0);
    bytes[55..87].copy_from_slice(&request.lease_id.0);
    bytes[87..91].copy_from_slice(&request.chunk_index.to_be_bytes());
    Ok(bytes)
}

fn decode_bulk_request(bytes: &[u8; BULK_REQUEST_BYTES]) -> io::Result<BulkRequest> {
    if &bytes[..6] != b"ASLB01" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let operation = BulkOperation::from_code(bytes[6])?;
    let chunk_index = u32::from_be_bytes(bytes[87..91].try_into().unwrap());
    validate_bulk_index(operation, chunk_index, io::ErrorKind::InvalidData)?;
    Ok(BulkRequest {
        operation,
        request_id: Id128(bytes[7..23].try_into().unwrap()),
        content_id: Hash32(bytes[23..55].try_into().unwrap()),
        lease_id: Hash32(bytes[55..87].try_into().unwrap()),
        chunk_index,
    })
}

fn validate_bulk_index(
    operation: BulkOperation,
    chunk_index: u32,
    error: io::ErrorKind,
) -> io::Result<()> {
    if operation != BulkOperation::Chunk && chunk_index != 0 {
        Err(error.into())
    } else {
        Ok(())
    }
}

fn encode_bulk_response(response: &BulkResponse) -> io::Result<Vec<u8>> {
    if response.payload.len() > MAX_BULK_PAYLOAD_BYTES
        || (response.status != BulkStatus::Success && !response.payload.is_empty())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = Vec::with_capacity(BULK_RESPONSE_HEADER_BYTES + response.payload.len());
    bytes.extend_from_slice(b"ASLR01");
    bytes.extend_from_slice(&response.request_id.0);
    bytes.push(response.status.code());
    bytes.extend_from_slice(
        &u32::try_from(response.payload.len())
            .map_err(|_| io::ErrorKind::InvalidInput)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&response.payload);
    Ok(bytes)
}

fn decode_bulk_response(bytes: &[u8]) -> io::Result<BulkResponse> {
    if bytes.len() < BULK_RESPONSE_HEADER_BYTES || &bytes[..6] != b"ASLR01" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let status = BulkStatus::from_code(bytes[22])?;
    let payload_length = u32::from_be_bytes(bytes[23..27].try_into().unwrap()) as usize;
    if payload_length > MAX_BULK_PAYLOAD_BYTES
        || payload_length != bytes.len() - BULK_RESPONSE_HEADER_BYTES
        || (status != BulkStatus::Success && payload_length != 0)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(BulkResponse {
        request_id: Id128(bytes[6..22].try_into().unwrap()),
        status,
        payload: bytes[BULK_RESPONSE_HEADER_BYTES..].to_vec(),
    })
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
    // libp2p request-response closes the sending half after each message.
    if io.read(&mut [0]).await? != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(payload)
}

async fn write_payload<T: AsyncWrite + Unpin>(io: &mut T, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(bytes).await
}
