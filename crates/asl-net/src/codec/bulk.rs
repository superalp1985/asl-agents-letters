use std::{fmt, io};

use asl_types::{
    ids::{Hash32, Id128},
    manifest::MAX_MANIFEST_LEN,
};
use libp2p::{
    StreamProtocol,
    futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    request_response::Codec,
};

use super::{check_protocol, require_eof};

pub const BULK_PROTOCOL: StreamProtocol = StreamProtocol::new("/asl/blob/1.0.0");
const REQUEST_BYTES: usize = 91;
const RESPONSE_HEADER_BYTES: usize = 27;
const MAX_RESPONSE_BYTES: usize = RESPONSE_HEADER_BYTES + MAX_MANIFEST_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkOperation {
    Manifest = 1,
    Chunk = 2,
    Inline = 3,
}

impl BulkOperation {
    fn from_code(code: u8) -> io::Result<Self> {
        match code {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::Chunk),
            3 => Ok(Self::Inline),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    fn permits_index(self, index: u32) -> bool {
        self == Self::Chunk || index == 0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BulkRequest {
    pub operation: BulkOperation,
    pub request_id: Id128,
    pub content_id: Hash32,
    pub lease_id: Hash32,
    pub chunk_index: u32,
}

impl fmt::Debug for BulkRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkRequest")
            .field("operation", &self.operation)
            .field("request_id", &self.request_id)
            .field("content_id", &self.content_id)
            .field("chunk_index", &self.chunk_index)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkStatus {
    Success = 0,
    NotFound = 1,
    Busy = 2,
    Expired = 3,
    IntegrityFailed = 4,
    Cancelled = 5,
}

impl BulkStatus {
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

    fn permits_length(self, length: usize) -> bool {
        length <= MAX_MANIFEST_LEN && (self == Self::Success || length == 0)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BulkResponse {
    pub request_id: Id128,
    pub status: BulkStatus,
    pub payload: Vec<u8>,
}

impl fmt::Debug for BulkResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkResponse")
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .field("payload_len", &self.payload.len())
            .finish()
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
        let mut bytes = [0; REQUEST_BYTES];
        io.read_exact(&mut bytes).await?;
        if &bytes[..6] != b"ASLB01" {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let operation = BulkOperation::from_code(bytes[6])?;
        let chunk_index = u32::from_be_bytes(bytes[87..91].try_into().unwrap());
        if !operation.permits_index(chunk_index) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        require_eof(io).await?;
        Ok(BulkRequest {
            operation,
            request_id: Id128(bytes[7..23].try_into().unwrap()),
            content_id: Hash32(bytes[23..55].try_into().unwrap()),
            lease_id: Hash32(bytes[55..87].try_into().unwrap()),
            chunk_index,
        })
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
        if !(RESPONSE_HEADER_BYTES..=MAX_RESPONSE_BYTES).contains(&length) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut header = [0; RESPONSE_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        if &header[..6] != b"ASLR01" {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let status = BulkStatus::from_code(header[22])?;
        let payload_length = u32::from_be_bytes(header[23..27].try_into().unwrap()) as usize;
        if payload_length != length - RESPONSE_HEADER_BYTES
            || !status.permits_length(payload_length)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut payload = vec![0; payload_length];
        io.read_exact(&mut payload).await?;
        require_eof(io).await?;
        Ok(BulkResponse {
            request_id: Id128(header[6..22].try_into().unwrap()),
            status,
            payload,
        })
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
        if !request.operation.permits_index(request.chunk_index) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut bytes = [0; REQUEST_BYTES];
        bytes[..6].copy_from_slice(b"ASLB01");
        bytes[6] = request.operation as u8;
        bytes[7..23].copy_from_slice(&request.request_id.0);
        bytes[23..55].copy_from_slice(&request.content_id.0);
        bytes[55..87].copy_from_slice(&request.lease_id.0);
        bytes[87..91].copy_from_slice(&request.chunk_index.to_be_bytes());
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
        let payload_length = response.payload.len();
        if !response.status.permits_length(payload_length) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let length = (RESPONSE_HEADER_BYTES + payload_length) as u32;
        let mut header = [0; 4 + RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&length.to_be_bytes());
        header[4..10].copy_from_slice(b"ASLR01");
        header[10..26].copy_from_slice(&response.request_id.0);
        header[26] = response.status as u8;
        header[27..31].copy_from_slice(&(payload_length as u32).to_be_bytes());
        io.write_all(&header).await?;
        io.write_all(&response.payload).await
    }
}
